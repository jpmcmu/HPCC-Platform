################################################################################
#    HPCC SYSTEMS software Copyright (C) 2012 HPCC Systems®.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
################################################################################

# Component: udptransport 

#####################################################
# Description:
# ------------
#    Cmake Input File for udptransport
#####################################################


project( udptransport ) 

set (    SRCS 
         uttest.cpp 
    )

include_directories ( 
         ./../../roxie/roxiemem 
         ./../../system/include 
         ./../../system/jlib 
         ./../../system/aeron/aeron-client/src/main/cpp 
         ./../../system/aeron/aeron-driver/src/main/c/
         ./../../system/aeron/aeron-samples/src/main/cpp  # temporary
         ./../../roxie/ccd 
         ./../../roxie/udplib
         ./../../common/thorhelper
         ./../../common/workunit
         ./../../rtl/include
         ./../../rtl/eclrtl
    )

ADD_DEFINITIONS ( -D_CONSOLE )
if (NOT WIN32)
  ADD_DEFINITIONS ( -Wno-format-nonliteral )
endif()

HPCC_ADD_EXECUTABLE ( udptransport ${SRCS} )
#install ( TARGETS udptransport RUNTIME DESTINATION ${EXEC_DIR} )
target_link_libraries ( udptransport 
         jlib
         roxiemem
         udplib 
    )

if (USE_AERON)
  target_link_libraries ( udptransport 
         aeron_client
         aeron_driver
    )
endif()

