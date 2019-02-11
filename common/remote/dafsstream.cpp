/*##############################################################################

    HPCC SYSTEMS software Copyright (C) 2019 HPCC Systems®.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
############################################################################## */

#include <atomic>
#include <string>
#include <array>
#include <unordered_map>

#include "platform.h"

#include "jfile.hpp"
#include "jflz.hpp"
#include "jlzw.hpp"
#include "jlog.hpp"
#include "jmisc.hpp"
#include "jptree.hpp"
#include "jsocket.hpp"

#include "dadfs.hpp"
#include "dafdesc.hpp"
#include "hqlexpr.hpp"
#include "rtlcommon.hpp"
#include "rtldynfield.hpp"
#include "eclhelper_dyn.hpp"

#include "sockfile.hpp"
#include "dafscommon.hpp"
#include "dafsstream.hpp"

namespace dafsstream
{

static const DFUFileOption defaultFileOptions = dfo_null;
static StringAttr defaultCompCompression = "LZ4";
static const char *DFUFileIdSeparator = "|";

class CDFUFile : public CSimpleInterfaceOf<IDFUFileAccess>, implements IDFUFileAccessExt
{
    typedef CSimpleInterfaceOf<IDFUFileAccess> PARENT;

    StringAttr name;
    StringAttr fileID;
    SecAccessFlags accessType = SecAccess_None;
    unsigned expirySecs = 300; // JCSMORE
    Owned<IPropertyTree> metaInfo;

    unsigned numParts = 0;
    bool grouped = false;
    DFUFileType fileType = dft_none;
    Owned<IOutputMetaData> actualMeta;
    Owned<IFileDescriptor> fileDesc;
    StringBuffer groupName;
    mutable MemoryBuffer binLayout;
    mutable CriticalSection decodeJsonCrit;
    mutable bool gotJsonTypeInfo = false;
    mutable StringBuffer jsonLayout;
    StringAttr metaInfoBlobB64;
    std::vector<std::string> hosts;
    DFUFileOption fileOptions = defaultFileOptions;
    StringAttr commCompType = defaultCompCompression;

public:
    IMPLEMENT_IINTERFACE_USING(PARENT);

    CDFUFile(const char *_metaInfoBlobB64, const char *_fileID) : metaInfoBlobB64(_metaInfoBlobB64), fileID(_fileID)
    {
        MemoryBuffer compressedMetaInfoMb;
        JBASE64_Decode(metaInfoBlobB64, compressedMetaInfoMb);
        MemoryBuffer decompressedMetaInfoMb;
        fastLZDecompressToBuffer(decompressedMetaInfoMb, compressedMetaInfoMb);
        Owned<IPropertyTree> metaInfoEnvelope = createPTree(decompressedMetaInfoMb);
        StringBuffer metaInfoSignature;
        if (metaInfoEnvelope->getProp("signature", metaInfoSignature))
        {
#if !defined(_USE_OPENSSL) || !defined(_WIN32)
            // implies will not be able to use this to communicate with secure dafilesrv's
#endif
            MemoryBuffer metaInfoBlob;
            metaInfoEnvelope->getPropBin("metaInfoBlob", metaInfoBlob);

            metaInfo.setown(createPTree(metaInfoBlob));
        }
        else
            metaInfo.set(metaInfoEnvelope);

        IPropertyTree *fileInfo = metaInfo->queryPropTree("FileInfo");
        unsigned metaInfoVersion = metaInfo->getPropInt("version");

        name.set(metaInfo->queryProp("logicalFilename"));

        switch (metaInfoVersion)
        {
            case 0:
                // implies unsigned direct request from engines (on unsecure port)
                // fall through
            case 1:
            {
                // old metaInfo, reconstruct a IFileDescriptor for ease of compatibility with rest of code

                unsigned numParts = fileInfo->getCount("Part");

                // calculate part mask
                const char *path = fileInfo->queryProp("Part[1]/Copy[1]/@filePath");
                StringBuffer dir, fname, ext;
                splitFilename(path, &dir, &dir, &fname, &ext);
                VStringBuffer partMask("%s._$P$_of_%u", fname.str(), numParts);

                // reconstruct group
                SocketEndpointArray eps;
                bool replicated = false;
                Owned<IPropertyTreeIterator> iter = fileInfo->getElements("Part");
                ForEach(*iter)
                {
                    IPropertyTree &part = iter->query();
                    if (part.hasProp("Copy[2]"))
                        replicated = true;
                    const char *host = part.queryProp("Copy[1]/@host");
                    SocketEndpoint ep(host);
                    eps.append(ep);
                }
                StringBuffer groupText;
                eps.getText(groupText);
                Owned<IGroup> group = createIGroup(eps);
                ClusterPartDiskMapSpec mspec;
                mspec.defaultCopies = replicated?DFD_DefaultCopies:DFD_NoCopies;

                fileDesc.setown(queryRemoteCreateFileDescriptorCB()(nullptr));
                fileDesc->setDefaultDir(dir.str());
                fileDesc->setNumParts(numParts);
                fileDesc->setPartMask(partMask);
                fileDesc->addCluster(group, mspec);
                break;
            }
            case 2: // serialized compact IFileDescriptor
            {
                fileDesc.setown(queryRemoteCreateFileDescriptorCB()(fileInfo));
                break;
            }
        }

        // JCSMORE - could/should I use fileDesc->queryKind() here?
        if (isFileKey(fileDesc))
            fileType = dft_index;
        else
            fileType = dft_flat;

        fileDesc->getClusterGroupName(0, groupName);
        grouped = fileDesc->isGrouped();
        numParts = fileDesc->numParts();

        hosts.resize(numParts*2); // typical max size
        for (unsigned p=0; p<numParts; p++)
        {
            unsigned numCopies = fileDesc->numCopies(p);
            for (unsigned c=0; c<numCopies; c++)
            {
                StringBuffer host;
                fileDesc->queryNode(p, c)->endpoint().getUrlStr(host);
                unsigned pos = p*numParts+c;
                if (hosts.size() <= pos)
                    hosts.resize(pos+1); // ensure big enough
                hosts.at(pos) = host.str();
            }
        }

        if (!metaInfo->getPropBin("binLayout", binLayout))
            throwUnexpected();
        actualMeta.setown(createTypeInfoOutputMetaData(binLayout, grouped));
        binLayout.reset(0);

        if (!fileID) // new esp client, construct a fileID (to be used for e.g. publish)
        {
            const char *clusterName = metaInfo->queryProp("clusterName");
            //create FileId
            StringBuffer tmp;
            tmp.set(groupName.str()).append(DFUFileIdSeparator).append(clusterName).append(DFUFileIdSeparator).append(name);
            fileID.set(tmp);
        }
    }
    const MemoryBuffer &queryBinTypeInfo() const
    {
        return binLayout;
    }
    const char *queryMetaInfoBlob() const
    {
        return metaInfoBlobB64;
    }
    IPropertyTree *queryMetaInfo() const
    {
        return metaInfo;
    }
// IDFUFileAccessExt
    virtual IOutputMetaData *queryMeta() const override
    {
        return actualMeta;
    }
    virtual IFileDescriptor &queryFileDescriptor() const
    {
        return *fileDesc;
    }
    virtual IPropertyTree &queryProperties() const override
    {
        return fileDesc->queryProperties();
    }
// IDFUFileAccess impl.
    virtual const char *queryName() const override
    {
        return name;
    }
    virtual const char *queryFileID() const override
    {
        return fileID;
    }
    virtual unsigned queryNumParts() const override
    {
        return numParts;
    }
    virtual SecAccessFlags queryAccessType() const
    {
        return accessType;
    }
    virtual bool queryIsGrouped() const override
    {
        return grouped;
    }
    virtual DFUFileType queryType() const override
    {
        return fileType;
    }
    virtual bool queryIsCompressed() const override
    {
        return fileDesc->isCompressed();
    }
    virtual const char *queryClusterGroupName() const override
    {
        return groupName;
    }
    virtual const char *queryPartHost(unsigned part, unsigned copy=0) const override
    {
        return hosts[part*numParts+copy].c_str();
    }
    virtual const char *queryJSONTypeInfo() const override
    {
        CriticalBlock b(decodeJsonCrit);
        if (!gotJsonTypeInfo)
        {
            Owned<IRtlFieldTypeDeserializer> deserializer = createRtlFieldTypeDeserializer();
            const RtlTypeInfo *typeInfo = deserializer->deserialize(binLayout.reset(0));
            if (!dumpTypeInfo(jsonLayout, typeInfo))
                throwUnexpected();
            gotJsonTypeInfo = true;
        }
        return jsonLayout;
    }
    virtual const char *queryECLRecordDefinition() const override
    {
        // JCSMORE
        CriticalBlock b(decodeJsonCrit);
        if (!gotJsonTypeInfo)
        {
            Owned<IRtlFieldTypeDeserializer> deserializer = createRtlFieldTypeDeserializer();
            const RtlTypeInfo *typeInfo = deserializer->deserialize(binLayout.reset(0));
            if (!dumpTypeInfo(jsonLayout, typeInfo))
                throwUnexpected();
            gotJsonTypeInfo = true;
        }
        return jsonLayout;
    }
    virtual const void *queryMetaInfoBlob(size32_t &sz) const override
    {
        sz = metaInfoBlobB64.length();
        return metaInfoBlobB64;
    }
    virtual const char *queryCommCompressionType() const override
    {
        return commCompType;
    }
    virtual void setCommCompressionType(const char *compType) override
    {
        commCompType.set(compType);
    }
    virtual DFUFileOption queryFileOptions() const override
    {
        return fileOptions;
    }
    virtual bool isFileOptionSet(DFUFileOption opt) const override
    {
        return ((unsigned)fileOptions | (unsigned)opt);
    }
    virtual const char *queryFileProperty(const char *name) const override
    {
        return fileDesc->queryProperties().queryProp(name);
    }
    virtual __int64 queryFilePropertyInt(const char *name) const override
    {
        return fileDesc->queryProperties().getPropInt64(name);
    }
    virtual const char *queryPartProperty(unsigned part, const char *name) const override
    {
        return fileDesc->queryPart(part)->queryProperties().queryProp(name);
    }
    virtual __int64 queryPartPropertyInt(unsigned part, const char *name) const override
    {
        return fileDesc->queryPart(part)->queryProperties().getPropInt64(name);
    }
    virtual void setFileOption(DFUFileOption opt) override
    {
        fileOptions = (DFUFileOption)(((unsigned)fileOptions) | (unsigned)opt);
    }
    virtual void clearFileOption(DFUFileOption opt) override
    {
        fileOptions = (DFUFileOption)(((unsigned)fileOptions) & ~((unsigned)opt));
    }
    virtual void setECLRecordDefinition(const char *eclRecDef) override
    {
        MemoryBuffer layoutBin;
        MultiErrorReceiver errs;
        Owned<IHqlExpression> expr = parseQuery(eclRecDef, &errs);
        if (errs.errCount() > 0)
        {
            StringBuffer errorMsg;
            throw makeStringExceptionV(0, "Failed in parsing ECL %s: %s.", eclRecDef, errs.toString(errorMsg).str());
        }
        if (!expr)
            throw makeStringExceptionV(0, "Failed in parsing ECL: %s.", eclRecDef);
        if (!exportBinaryType(layoutBin, expr, false))
            throw MakeStringException(0, "Failed in exportBinaryType.");

        fileDesc->queryProperties().setProp("ECL", eclRecDef);
        fileDesc->queryProperties().setPropBin("_rtlType", layoutBin.length(), layoutBin.toByteArray());
    }
    virtual void setFileProperty(const char *name, const char *value) override
    {
        fileDesc->queryProperties().setProp(name, value);
    }
    virtual void setFilePropertyInt(const char *name, __int64 value) override
    {
        fileDesc->queryProperties().setPropInt64(name, value);
    }
    virtual void setPartProperty(unsigned part, const char *name, const char *value) override
    {
        fileDesc->queryPart(part)->queryProperties().setProp(name, value);
    }
    virtual void setPartPropertyInt(unsigned part, const char *name, __int64 value) override
    {
        fileDesc->queryPart(part)->queryProperties().setPropInt64(name, value);
    }
// NB: the intention is for a IDFUFileAccess to be used to create instances for multiple parts, but not to mix types.
    virtual IDFUFilePartReader *createFilePartReader(unsigned p, unsigned copy, IOutputMetaData *outMeta) override;
    virtual IDFUFilePartWriter *createFilePartWriter(unsigned p) override;

    virtual IDFUFileAccessExt *queryEngineInterface() override { return this; }
};

IDFUFileAccess *createDFUFileAccess(const char *metaInfoBlobB64, const char *fileID)
{
    return new CDFUFile(metaInfoBlobB64, fileID);
}


class CDaFileSrvClientBase : public CInterfaceOf<IDFUFilePartBase>
{
protected:
    Linked<CDFUFile> file;
    unsigned part = 0;
    unsigned copy = 0;
    Owned<IPropertyTree> requestTree;
    IPropertyTree *requestNode = nullptr;
    size32_t jsonRequestStartPos = 0;
    size32_t jsonRequestEndPos = 0;
    MemoryBuffer sendMb;
    Owned<IDaFsConnection> daFsConnection;
    int handle = 0;
    unsigned serverVersion = 0;
    unsigned rowStreamReplyMb = 1024; // MB
    bool started = false;

    bool checkAccess(SecAccessFlags accessWanted)
    {
        return 0 != (file->queryAccessType() & accessWanted);
    }
    void markJsonStart()
    {
        sendMb.append((size32_t)0); // placeholder
        jsonRequestStartPos = sendMb.length();
    }
    void markJsonEnd()
    {
        jsonRequestEndPos = sendMb.length();
        size32_t jsonRequestLen = jsonRequestEndPos - jsonRequestStartPos;
        sendMb.writeEndianDirect(jsonRequestStartPos-sizeof(size32_t), sizeof(size32_t), &jsonRequestLen);
    }
    void serializeJsonRequest(IPropertyTree *tree)
    {
        StringBuffer jsonStr;
#if _DEBUG
        toJSON(tree, jsonStr, 2);
#else
        toJSON(tree, jsonStr, 0, 0);
#endif
        sendMb.append(jsonStr.length(), jsonStr); // NB: if there was a IOStream to MemoryBuffer impl, could use that to avoid encoding to string, and then appending.
    }
    void addRequest(IPropertyTree *tree, RemoteFileCommandType legacyCmd=RFCunknown)
    {
        if (serverVersion < DAFILESRV_STREAMGENERAL_MINVERSION)
        {
            assertex(legacyCmd != RFCunknown);
            sendMb.append(legacyCmd);
            serializeJsonRequest(tree);
        }
        else
        {
            sendMb.append((RemoteFileCommandType)RFCStreamGeneral);
            markJsonStart();
            serializeJsonRequest(tree);
            markJsonEnd();
        }
    }
    unsigned send(MemoryBuffer &reply)
    {
        daFsConnection->send(sendMb, reply);
        unsigned newHandle;
        reply.read(newHandle);
        return newHandle;
    }
    void establishServerVersion()
    {
        if (serverVersion)
            return;
        serverVersion = getCachedRemoteVersion(*daFsConnection); // NB: may also connect in the process
        if (0 == serverVersion)
        {
            StringBuffer str;
            throw makeStringExceptionV(0, "CDaFileSrvClientBase: Failed to connect to %s", daFsConnection->queryEp().getUrlStr(str).str());
        }

        if (serverVersion < DAFILESRV_STREAMREAD_MINVERSION)
        {
            StringBuffer str;
            throw makeStringExceptionV(0, "CDaFileSrvClientBase: serversion(%u), too old connect to %s", serverVersion, daFsConnection->queryEp().getUrlStr(str).str());
        }
    }
    void start()
    {
        establishServerVersion(); // JCSMORE - ensure cache involved behind the scenes
    }
    void close()
    {
        daFsConnection->close(handle);
    }
public:
    CDaFileSrvClientBase(CDFUFile *_file, unsigned _part, unsigned _copy) : file(_file), part(_part), copy(_copy)
    {
        unsigned port = file->queryMetaInfo()->getPropInt("port");
        bool secure = file->queryMetaInfo()->getPropBool("secure");
        SocketEndpoint ep(file->queryPartHost(part), port);
        DAFSConnectCfg connMethod = secure ? SSLOnly : SSLNone;
        daFsConnection.setown(createDaFsConnection(ep, connMethod, file->queryName()));

        requestTree.setown(createPTree());
        requestTree->setProp("format", "binary");
        requestTree->setPropInt("replyLimit", rowStreamReplyMb);
        if (file->isFileOptionSet(dfo_compressedRemoteStreams))
            requestTree->setProp("commCompression", file->queryCommCompressionType());
        requestNode = requestTree->setPropTree("node");


        // NB: these are 1 based
        requestNode->setPropInt("filePart", part+1);
        requestNode->setPropInt("filePartCopy", copy+1);
        const MemoryBuffer &binLayout = file->queryBinTypeInfo();
        StringBuffer typeInfoStr;
        JBASE64_Encode(binLayout.toByteArray(), binLayout.length(), typeInfoStr, false);
        requestNode->setProp("inputBin", typeInfoStr.str()); // on disk meta
        requestNode->setProp("metaInfo", file->queryMetaInfoBlob());
    }
    virtual void beforeDispose() override
    {
        try
        {
            finalize();
        }
        catch (IException *e)
        {
            EXCLOG(e, nullptr);
            e->Release();
        }
    }
// IDFUFilePartBase impl.
    virtual void finalize() override
    {
        close();
        started = false;
    }
};

class CDFUPartReader : public CDaFileSrvClientBase, implements IDFUFilePartReader, implements ISerialStream
{
    typedef CDaFileSrvClientBase PARENT;

    MemoryBuffer replyMb;
    Owned<IExpander> expander;
    MemoryBuffer expandMb;
    size32_t bufRemaining = 0;
    offset_t bufPos = 0;
    bool endOfStream = false;
    std::unordered_map<std::string, std::string> virtualFields;
    Owned<ISourceRowPrefetcher> rowPrefetcher;
    CThorContiguousRowBuffer prefetchBuffer;
    bool grouped = false;
    bool eog = false;
    bool eoi = false;
    Linked<IOutputMetaData> outMeta;
    const byte *bufPtr = nullptr;
    offset_t currentReadPos = 0;
    bool variableContentDirty = false;
    bool pendingFinishRow = false;
    std::vector<std::string> fieldFilters;

    void ensureAvailable()
    {
        replyMb.read(bufRemaining);
        endOfStream = (bufRemaining == 0); // NB: if true, a cursorLength of 0 will follow.
        if (expander && !endOfStream)
        {
            size32_t compressedRowDataSz;
            replyMb.read(compressedRowDataSz);

            size32_t expandedSz = expander->init(replyMb.bytes()+replyMb.getPos(), compressedRowDataSz);
            expandMb.clear().reserve(expandedSz);
            expander->expand(expandMb.bufferBase());
            expandMb.swapWith(replyMb);
        }
        bufPtr = replyMb.bytes()+replyMb.getPos();
        // NB: continuation cursor (with leading length) follows the row data in replyMb, 0 if no more row data
    }
    void ensureVariableContentAdded()
    {
        if (!variableContentDirty)
            return;
        variableContentDirty = false;

        IPropertyTree *virtualFieldsTree = requestNode->setPropTree("virtualFields");
        for (auto &e : virtualFields)
            virtualFieldsTree->setProp(e.first.c_str(), e.second.c_str());

        while (requestNode->removeProp("keyFilter")); // remove all
        for (auto &field: fieldFilters)
            requestNode->addProp("keyFilter", field.c_str());
    }
    unsigned sendReadStart()
    {
        ensureVariableContentAdded();
        sendMb.clear();
        initSendBuffer(sendMb);
        addRequest(requestTree, RFCStreamRead);

        unsigned newHandle = send(replyMb.clear());
        ensureAvailable(); // reads from replyMb
        return newHandle;
    }
    unsigned sendReadContinuation(MemoryBuffer &newReply)
    {
        sendMb.clear();
        initSendBuffer(sendMb);
        Owned<IPropertyTree> tree = createPTree();
        tree->setPropInt("handle", handle);
        addRequest(tree, RFCStreamRead);

        daFsConnection->send(sendMb, newReply);
        unsigned newHandle;
        newReply.read(newHandle);
        return newHandle;
    }
    void extendReplyMb(size32_t wanted)
    {
        if (0 == bufRemaining)
        {
            refill();
            return;
        }
        MemoryBuffer newReplyMb;
        size32_t oldRemaining = bufRemaining;
        size32_t leadingSpace = bufRemaining;
        size32_t hdrSize = sizeof(handle) + sizeof(bufRemaining);
        if (leadingSpace > hdrSize)
            leadingSpace -= hdrSize;
        // reserve space to insert what remains in current replyMb into new, to ensure contiguous
        newReplyMb.ensureCapacity(leadingSpace);

        // ensures gets in one go
        if (wanted>rowStreamReplyMb) // unlikely
            requestTree->setPropInt("replyLimit", wanted);

        unsigned newHandle = sendReadContinuation(newReplyMb);
        if (newHandle == handle)
            replyMb.swapWith(newReplyMb);
        else // dafilesrv did not recognize handle, send cursor
        {
            assertex(newHandle == 0);
            // resend original request with cursor
            size32_t cursorLength;
            replyMb.skip(bufRemaining);
            replyMb.read(cursorLength);
            requestTree->setPropBin("cursorBin", cursorLength, replyMb.readDirect(cursorLength));
            handle = sendReadStart(); // new handle
        }
        ensureAvailable(); // reads from replyMb
        // now have read new handle and new bufRemaining, copy it back to reserved space
        replyMb.writeDirect(0, oldRemaining, newReplyMb.readDirect(oldRemaining)); // NB: newReplyMb was swapped and refers to old here
        bufRemaining += oldRemaining;
        bufPtr = replyMb.bytes();
        replyMb.reset(0); // read pos
    }
    void refill()
    {
        if (!started)
            throw makeStringException(0, "CDFUPartReader - not started");
        size32_t cursorLength;
        if (replyMb.needSwapEndian())
            _cpyrevn(&cursorLength, bufPtr, sizeof(cursorLength));
        else
            memcpy(&cursorLength, bufPtr, sizeof(cursorLength));
        if (!cursorLength)
        {
            endOfStream = true;
            return;
        }
        MemoryBuffer newReply;
        unsigned newHandle = sendReadContinuation(newReply);
        if (newHandle == handle)
            replyMb.swapWith(newReply);
        else // dafilesrv did not recognize handle, send cursor
        {
            assertex(newHandle == 0);
            // resend original request with cursor
            requestTree->setPropBin("cursorBin", cursorLength, replyMb.readDirect(cursorLength));
            handle = sendReadStart(); // new handle
        }
        ensureAvailable(); // reads from replyMb
    }
// ISerialStream impl.
    virtual const void *peek(size32_t wanted, size32_t &got) override
    {
        if (bufRemaining >= wanted)
        {
            got = bufRemaining;
            return bufPtr;
        }
        extendReplyMb(wanted);
        got = bufRemaining;
        return bufPtr;
    }
    virtual void get(size32_t len, void * ptr) override               // exception if no data available
    {
        while (len)
        {
            if (0 == bufRemaining)
            {
                refill();
                if (0 == bufRemaining)
                    throw makeStringException(0, "CDFUPartReader::get(): end of stream");
            }
            size32_t r = len>bufRemaining ? bufRemaining : len;
            memcpy(ptr, bufPtr, r);
            len -= r;
            bufRemaining -= r;
            bufPtr += r;
            currentReadPos += r;
        }
    }
    virtual bool eos() override
    {
        if (!eoi)
        {
            if (0 == bufRemaining)
            {
                refill();
                if (0 == bufRemaining)
                    eoi = true;
            }
        }
        return eoi;
    }
    virtual void skip(size32_t len) override
    {
        // same as get() without the memcpy
        while (len)
        {
            if (0 == bufRemaining)
            {
                refill();
                if (0 == bufRemaining)
                    throw makeStringException(0, "CDFUPartReader::skip(): end of stream");
            }
            size32_t r = len>bufRemaining ? bufRemaining : len;
            len -= r;
            bufRemaining -= r;
            bufPtr += r;
            currentReadPos += r;
        }
    }
    virtual offset_t tell() const override
    {
        return currentReadPos;
    }
    virtual void reset(offset_t _offset,offset_t _flen=(offset_t)-1) override
    {
        throwUnexpected();
    }
public:
    IMPLEMENT_IINTERFACE_USING(PARENT);

    CDFUPartReader(CDFUFile *file, unsigned part, unsigned copy, IOutputMetaData *_outMeta) : CDaFileSrvClientBase(file, part, copy), outMeta(_outMeta), prefetchBuffer(nullptr)
    {
        checkAccess(SecAccess_Read);
        grouped = file->queryIsGrouped();

        // NB: setOutputRecordFormat() can override/set outMeta
        if (outMeta && (outMeta != file->queryMeta()))
        {
            MemoryBuffer projectedTypeInfo;
            dumpTypeInfo(projectedTypeInfo, outMeta->querySerializedDiskMeta()->queryTypeInfo());
            StringBuffer typeInfoStr;
            JBASE64_Encode(projectedTypeInfo.toByteArray(), projectedTypeInfo.length(), typeInfoStr, false);
            const char *inputBin = requestNode->queryProp("inputBin"); // NB: this is disk meta
            if (0 != strsame(typeInfoStr, inputBin)) // double check provided outMeta is not same as inMeta
                requestNode->setProp("outputBin", typeInfoStr.str()); // i.e. dafilesrv will project to this meta
        }
        else
            outMeta.set(file->queryMeta());

        if (file->queryIsCompressed())
            requestNode->setPropBool("compressed", true);
        if (grouped)
            requestNode->setProp("inputGrouped", "true");

        switch (file->queryType())
        {
            case dft_flat:
                requestNode->setProp("kind", "diskread");
                break;
            case dft_index:
            {
                requestNode->setProp("kind", "indexread");
                break;
            }
            default:
                throwUnexpected();
        }

        if (file->isFileOptionSet(dfo_compressedRemoteStreams))
        {
            expander.setown(getExpander(file->queryCommCompressionType()));
            if (expander)
                expandMb.setEndian(__BIG_ENDIAN);
            else
                throw makeStringExceptionV(0, "Failed to created compression decompressor for: %s", file->queryCommCompressionType());
        }
    }
// IDFUFilePartReader impl.
    virtual void start() override
    {
        PARENT::start();
        rowPrefetcher.setown(outMeta->createDiskPrefetcher());
        assertex(rowPrefetcher);
        prefetchBuffer.setStream(this);
        eog = false;
        eoi = false;
        pendingFinishRow = false;
        handle = sendReadStart();
        started = true;
    }
    virtual void finalize() override
    {
        PARENT::finalize();
    }
    virtual IOutputMetaData *queryMeta() const override
    {
        return outMeta;
    }
    virtual const void *nextRow(size32_t &sz) override
    {
        if (pendingFinishRow)
        {
            pendingFinishRow = false;
            prefetchBuffer.finishedRow();
        }
        if (eog)
            eog = false;
        else if (!eoi)
        {
            if (prefetchBuffer.eos())
            {
                eoi = true;
                return nullptr;
            }
            rowPrefetcher->readAhead(prefetchBuffer);
            const byte * row = prefetchBuffer.queryRow();
            sz = prefetchBuffer.queryRowSize();
            pendingFinishRow = true;
            if (grouped)
                prefetchBuffer.read(sizeof(eog), &eog);
            return row;
        }
        return nullptr;
    }
    virtual const void *getRows(size32_t min, size32_t &got) override
    {
        if (pendingFinishRow)
        {
            pendingFinishRow = false;
            prefetchBuffer.finishedRow();
        }
        if (eoi)
        {
            got = 0;
            return nullptr;
        }
        while (true)
        {
            if (prefetchBuffer.eos())
            {
                eoi = true;
                got = prefetchBuffer.queryRowSize();
                return got ? prefetchBuffer.queryRow() : nullptr;
            }
            rowPrefetcher->readAhead(prefetchBuffer);
            pendingFinishRow = true;
            if (grouped)
                prefetchBuffer.read(sizeof(eog), &eog);
            got = prefetchBuffer.queryRowSize();
            if (got >= min)
                return prefetchBuffer.queryRow();
        }
        got = 0;
        return nullptr;
    }
// NB: the methods below should be called before start()
    virtual void addFieldFilter(const char *textFilter) override
    {
        // this is purely to validate the textFilter
        const RtlRecord *record = &file->queryMeta()->queryRecordAccessor(true);
        Owned<IFieldFilter> rtlFilter = deserializeFieldFilter(*record, textFilter);

        fieldFilters.push_back(textFilter);
        variableContentDirty = true;
    }
    virtual void clearFieldFilters() override
    {
        fieldFilters.clear();
        variableContentDirty = true;
    }
    virtual void setOutputRecordFormat(const char *eclRecDef) override
    {
        MultiErrorReceiver errs;
        Owned<IHqlExpression> record = parseQuery(eclRecDef, &errs);
        if (errs.errCount())
        {
            StringBuffer errText;
            IError *first = errs.firstError();
            first->toString(errText);
            throw makeStringExceptionV(0, "Failed to parse output ecl definition '%s': %s @ %u:%u", eclRecDef, errText.str(), first->getColumn(), first->getLine());
        }
        if (!record)
            throw makeStringExceptionV(0, "Failed to parse output ecl definition '%s'", eclRecDef);

        MemoryBuffer projectedTypeInfo;
        exportBinaryType(projectedTypeInfo, record, dft_index == file->queryType());
        outMeta.setown(createTypeInfoOutputMetaData(projectedTypeInfo, false)); // JCSMORE if file->queryIsGrouped(), should this be? and if so, ctor outMeta needs reconstructing
        StringBuffer typeInfoStr;
        JBASE64_Encode(projectedTypeInfo.toByteArray(), projectedTypeInfo.length(), typeInfoStr, false);
        requestNode->setProp("outputBin", typeInfoStr.str());
    }
    virtual void addVirtualFieldMapping(const char *fieldName, const char *fieldValue) override
    {
        variableContentDirty = true;
        virtualFields[fieldName] = fieldValue;
    }
};


class CDFUPartWriterBase : public CDaFileSrvClientBase, implements IDFUFilePartWriter
{
    typedef CDaFileSrvClientBase PARENT;

    MemoryBuffer replyMb;
    bool firstSend = true;
    unsigned startPos = 0;
    Owned<ICompressor> compressor;

protected:
    const unsigned sendThresholdBytes = 0x100000; // 1MB

    void prepNext()
    {
        sendMb.clear();
        // prepare for next continuation
        initSendBuffer(sendMb);
        Owned<IPropertyTree> tree = createPTree();
        tree->setPropInt("handle", handle);
        addRequest(tree);
        startPos = sendMb.length();
        size32_t rowDataSz = 0;
        sendMb.append(rowDataSz); // place holder
        if (compressor)
        {
            void *rowData = sendMb.reserveTruncate(sendThresholdBytes);
            compressor->open(rowData, sendThresholdBytes);
        }
    }
    unsigned send(MemoryBuffer &replyMb)
    {
        size32_t len;
        if (compressor)
        {
            compressor->close();
            len = compressor->buflen();
            sendMb.setLength(startPos + sizeof(len)+len);
        }
        else
            len = sendMb.length()-startPos;
        sendMb.writeEndianDirect(startPos, sizeof(len), &len);
        return PARENT::send(replyMb);
    }
    void _sendWriteFirst()
    {
        unsigned newHandle = send(replyMb.clear());
        if (!newHandle)
            throwStringExceptionV(DAFSERR_cmdstream_generalwritefailure, "Error whilst writing data to file: '%s'", file->queryName());
        else if (handle && (newHandle != handle))
            throwStringExceptionV(DAFSERR_cmdstream_unknownwritehandle, "Unknown write handle whilst remote writing to file: '%s'", file->queryName());
        handle = newHandle;
    }
    void sendWriteFirst()
    {
        _sendWriteFirst();
        prepNext();
    }
    unsigned sendWriteContinuation()
    {
        MemoryBuffer newReplyMb;
        unsigned newHandle = send(newReplyMb.clear());
        if (newHandle == handle)
            replyMb.swapWith(newReplyMb);
        else // dafilesrv did not recognize handle, send cursor
        {
            assertex(newHandle == 0);
            // resend original request with cursor
            size32_t cursorLength;
            replyMb.read(cursorLength);
            requestTree->setPropBin("cursorBin", cursorLength, replyMb.readDirect(cursorLength));
            initSendBuffer(sendMb);
            addRequest(requestTree);
            _sendWriteFirst(); // new handle
        }
        prepNext();
        return newHandle;
    }
    void sendWrite()
    {
        if (firstSend) // for 1st send, want to send even if no record, so that file is at least created
        {
            if (!started)
                throw makeStringException(0, "CDFUPartWriterBase: start() must be called before write()");
            firstSend = false;
            sendWriteFirst();
        }
        else if (sendMb.length() > startPos) // if anything to send
            sendWriteContinuation();
    }
public:
    IMPLEMENT_IINTERFACE_USING(PARENT);

    CDFUPartWriterBase(CDFUFile *file, unsigned part) : CDaFileSrvClientBase(file, part, 0)
    {
        if (file->isFileOptionSet(dfo_compressedRemoteStreams))
        {
            compressor.setown(getCompressor(file->queryCommCompressionType()));
            if (!compressor)
                WARNLOG("Failed to created compressor for: %s", file->queryCommCompressionType());
        }
    }
// IDFUFilePartWriter impl.
    virtual void start() override
    {
        PARENT::start();

        if (serverVersion < DAFILESRV_STREAMGENERAL_MINVERSION)
            throw makeStringExceptionV(0, "dafilesrv version (%u) too old to support streaming write", serverVersion);

        sendMb.clear();
        initSendBuffer(sendMb);
        addRequest(requestTree);
        startPos = sendMb.length();
        size32_t rowDataSz = 0;
        sendMb.append(rowDataSz); // place holder
        if (compressor)
        {
            void *rowData = sendMb.reserveTruncate(sendThresholdBytes);
            compressor->open(rowData, sendThresholdBytes);
        }
        started = true;
    }
    virtual void finalize() override
    {
        if (!started)
            return;
        sendWrite();
        PARENT::finalize();
    }
    virtual IOutputMetaData *queryMeta() const override
    {
        return file->queryMeta();
    }
    virtual void write(size32_t sz, const void *rowData) override // NB: can be multiple rows
    {
        if (compressor)
        {
            if (compressor->write(rowData, sz) < sz)
                sendWrite();
        }
        else
        {
            sendMb.append(sz, rowData);
            if (sendMb.length() > sendThresholdBytes)
                sendWrite();
        }
    }
};

static const char *defaultCompressionType = "LZ4";
class CDFUPartFlatWriter : public CDFUPartWriterBase
{
    StringAttr eclRecDef;
public:
    CDFUPartFlatWriter(CDFUFile *file, unsigned part) : CDFUPartWriterBase(file, part)
    {
        checkAccess(SecAccess_Write);
        if (dft_flat != file->queryType())
            throw makeStringExceptionV(0, "CDFUPartFlatWriter: invalid file type: %u", file->queryType());

        requestNode->setProp("kind", "diskwrite");
        if (file->queryIsCompressed())
            requestNode->setProp("compressed", defaultCompressionType);
        requestNode->setProp("inputGrouped", boolToStr(file->queryIsGrouped()));
    }
};

class CDFUPartIndexWriter : public CDFUPartWriterBase
{
    StringAttr eclRecDef;
public:
    CDFUPartIndexWriter(CDFUFile *file, unsigned part) : CDFUPartWriterBase(file, part)
    {
        checkAccess(SecAccess_Write);
        if (dft_index != file->queryType())
            throw makeStringExceptionV(0, "CDFUPartIndexWriter: invalid file type: %u", file->queryType());

        requestNode->setProp("kind", "indexwrite");
    }
};



IDFUFilePartReader *CDFUFile::createFilePartReader(unsigned p, unsigned copy, IOutputMetaData *outMeta)
{
    return new CDFUPartReader(this, p, copy, outMeta);
}

IDFUFilePartWriter *CDFUFile::createFilePartWriter(unsigned p)
{
    switch (fileType)
    {
        case dft_flat:
            return new CDFUPartFlatWriter(this, p);
        case dft_index:
            return new CDFUPartIndexWriter(this, p);
        default:
            throwUnexpected();
    }
}

////////////

IRowWriter *createRowWriter(IDFUFilePartWriter *partWriter)
{
    class CRowWriter : public CSimpleInterfaceOf<IRowWriter>, protected IRowSerializerTarget
    {
        Linked<IDFUFilePartWriter> partWriter;
        IOutputMetaData *meta = nullptr;
        Owned<IOutputRowSerializer> serializer;
        unsigned nesting = 0;
        MemoryBuffer nested;

    // IRowSerializerTarget impl.
        virtual void put(size32_t len, const void * ptr) override
        {
            if (nesting)
                nested.append(len, ptr);
            else
                partWriter->write(len, ptr);
        }
        virtual size32_t beginNested(size32_t count) override
        {
            nesting++;
            unsigned pos = nested.length();
            nested.append((size32_t)0);
            return pos;
        }
        virtual void endNested(size32_t sizePos) override
        {
            size32_t sz = nested.length()-(sizePos + sizeof(size32_t));
            nested.writeDirect(sizePos,sizeof(sz),&sz);
            nesting--;
            if (!nesting)
            {
                partWriter->write(nested.length(), nested.toByteArray());
                nested.clear();
            }
        }
    public:
        CRowWriter(IDFUFilePartWriter *_partWriter) : partWriter(_partWriter)
        {
            meta = partWriter->queryMeta();
            serializer.setown(meta->createDiskSerializer(nullptr, 1));
        }
        virtual void putRow(const void *row) override
        {
            serializer->serialize(*this, (const byte *)row);
// JCSMORE consider grouping
        }
        virtual void flush() override
        {
            // flushing internal to partWriter
        }
    };
    return new CRowWriter(partWriter);
}

IRowStream *createRowStream(IDFUFilePartReader *partReader)
{
    class CRowStream : public CSimpleInterfaceOf<IRowStream>
    {
        IDFUFilePartReader *partReader;
    public:
        CRowStream(IDFUFilePartReader *_partReader) : partReader(_partReader)
        {
        }
        virtual const void *nextRow() override
        {
            return nullptr;
        }
        virtual void stop() override
        {
        }
    };
    return new CRowStream(partReader);
}

void setDefaultCommCompression(const char *compType)
{
    defaultCompCompression.set(compType);
}


} // namespace dafsstream
