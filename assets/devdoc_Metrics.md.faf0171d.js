import{_ as e,o as t,c as a,O as s}from"./chunks/framework.28ebbb68.js";const f=JSON.parse('{"title":"Metrics Framework Design","description":"","frontmatter":{},"headers":[],"relativePath":"devdoc/Metrics.md","filePath":"devdoc/Metrics.md"}'),n={name:"devdoc/Metrics.md"},o=s(`<h1 id="metrics-framework-design" tabindex="-1">Metrics Framework Design <a class="header-anchor" href="#metrics-framework-design" aria-label="Permalink to &quot;Metrics Framework Design&quot;">​</a></h1><h2 id="introduction" tabindex="-1">Introduction <a class="header-anchor" href="#introduction" aria-label="Permalink to &quot;Introduction&quot;">​</a></h2><p>This document describes the design of a metrics framework that allows HPCC Systems components to implement a metric collection strategy. Metrics provide the following functionality:</p><ul><li><p>Alerts and monitoring</p><p>An important DevOps function is to monitor the cluster and providing alerts when problems are detected. Aggregated metric values from multiple sources provide the necessary data to build a complete picture of cluster health that drives monitoring and alerts.</p></li><li><p>Scaling</p><p>As described above, aggregated metric data is also used to dynamically respond to changing cluster demands and load. Metrics provide the monitoring capability to react and take action</p></li><li><p>Fault diagnosis and resource monitoring</p><p>Metrics provide historical data useful in diagnosing problems by profiling how demand and usage patterns may change prior to a fault. Predictive analysis can also be applied.</p></li><li><p>Analysis of jobs/workunits and profiling</p><p>With proper instrumentation, a robust dynamic metric strategy can track workunit processing. Internal problems with queries should be diagnosed from deep drill down logging.</p></li></ul><p>The document consists of several sections in order to provide requirements as well as the design of framework components.</p><h3 id="definitions" tabindex="-1">Definitions <a class="header-anchor" href="#definitions" aria-label="Permalink to &quot;Definitions&quot;">​</a></h3><p>Some definitions are useful.</p><p>Metric</p><p>: A measurement defined by a component that represents an internal state that is useful in a system reliability engineering function. In the context of the framework, a metric is an object representing the above.</p><p>Metric Value</p><p>: The current value of a metric.</p><p>Metric Updating</p><p>: The component task of updating metric state.</p><p>Collection</p><p>: A framework process of selecting relevant metrics based on configuration and then retrieving their values.</p><p>Reporting</p><p>: A framework process of converting values obtained during a collection into a format suitable for ingestion by a collection system.</p><p>Trigger</p><p>: What causes the collection of metric values.</p><p>Collection System</p><p>: The store for metric values generated during the reporting framework process.</p><h2 id="use-scenarios" tabindex="-1">Use Scenarios <a class="header-anchor" href="#use-scenarios" aria-label="Permalink to &quot;Use Scenarios&quot;">​</a></h2><p>This section describes how components expect to use the framework. It is not a complete list of all requirements but rather a sample.</p><h3 id="roxie" tabindex="-1">Roxie <a class="header-anchor" href="#roxie" aria-label="Permalink to &quot;Roxie&quot;">​</a></h3><p>Roxie desires to keep a count of many different internal values. Some examples are</p><ul><li><p>Disk type operations such as seeks and reads</p></li><li><p>Execution totals</p><p>Need to track items such as total numbers of items such as success and failures as well as breaking some counts into individual reasons. For example, failures may need be categorized such as as</p><ul><li>Busy</li><li>Timeout</li><li>Bad input</li></ul><p>Or even by priority (high, low, sla, etc.)</p></li><li><p>Current operational levels such as the length of internal queues</p></li><li><p>The latency of operations such as queue results, agent responses, and gateway responses</p></li></ul><p>Roxie also has the need to track internal memory usage beyond the pod/system level capabilities. Tracking the state of its large fixed memory pool is necessary.</p><p>The Roxie buddy system also must track how often and who is completing requests. The &quot;I Beat You To It&quot; set of metrics must be collected and exposed in order to detect pending node failure. While specific action on these counts is not known up front, it appears clear that these values are useful and should be collected.</p><p>There does not appear to be a need for creating and destroying metrics dynamically. The set of metrics is most likely to be created at startup and remain active through the life of the Roxie. If, however, stats collection seeps into the metrics framework, dynamic creation and destruction of stats metrics is a likely requirement.</p><h3 id="esp" tabindex="-1">ESP <a class="header-anchor" href="#esp" aria-label="Permalink to &quot;ESP&quot;">​</a></h3><p>There are some interesting decisions with respect to ESP and collection of metrics. Different applications within ESP present different use cases for collection. Ownership of a given task drives some of these use cases. Take workunit queues. If ownership of the task, with respect to metrics, is WsWorkunits, then use cases are centric to that component. However, if agents listening on the queue are to report metrics, then a different set of use cases emerge. It is clear that additional work is needed to generate clear ownership of metrics gathered by ESP and/or the tasks it performs.</p><p>ESP needs to report the <em>activeTransactions</em> value from the TxSummary class(es). This gives an indication of how busy the ESP is in terms of client requests.</p><p>Direct measurement of response time in requests may not be useful since the type of request causes different execution paths within ESP that are expected to take widely varying amounts of time. Creation of metrics for each method is not recommended. However, two possible solutions are to a) create a metric for request types, or b) use a histogram to measure response time ranges. Another option mentioned redefines the meaning of a bucket in a histogram. Instead of a numeric distribution, each bucket represents a unique subtask within an overall &quot;metric&quot; representing a measured operation. This should be explored whether for operational or developmental purposes.</p><p>For tracking specific queries and their health, the feeling is that logging can accomplish this better than metrics since the list of queries to monitor will vary between clusters. Additionally, operational metrics solving the cases mentioned above will give a view into the overall health of ESP which will affect the execution of queries. Depending on actions taken by these metrics, scaling may solve overload conditions to keep cluster responsiveness acceptable.</p><p>For Roxie a workunit operates as a service. Measuring service performance using a histogram to capture response times as a distribution may be appropriate. Extracting the 95th percentile of response time may be useful as well.</p><p>There are currently no use cases requiring consistency between values of different metrics.</p><p>At this time the only concrete metric identified is the number of requests received. As the framework design progresses and ESP is instrumented, the list will grow.</p><h3 id="dali-use-cases" tabindex="-1">Dali Use Cases <a class="header-anchor" href="#dali-use-cases" aria-label="Permalink to &quot;Dali Use Cases&quot;">​</a></h3><p>From information gathered, Dali plans to keep counts and rates for many of the items it manages.</p><h2 id="framework-design" tabindex="-1">Framework Design <a class="header-anchor" href="#framework-design" aria-label="Permalink to &quot;Framework Design&quot;">​</a></h2><p>This section covers the design and architecture of the framework. It discusses the main areas of the design, the interactions between each area, and an overall process model of how the framework operates.</p><p>The framework consists of three major areas: metrics, sinks, and the glue logic. These areas work together with the platform and the component to provide a reusable metrics collection function.</p><p>Metrics represent the quantifiable component state measurements used to track and assess the status of the component. Metrics are typically scalar values that are easily aggregated by a collection system. Aggregated values provide the necessary input to take component and cluster actions such as scaling up and down. The component is responsible for creating metrics and instrumenting the code. The framework provides the support for collecting and reporting the values. Metrics provide the following:</p><ul><li>Simple methods for the component to update the metric</li><li>Simple methods for the framework to retrieve metric value(s)</li><li>Handling of all synchronization between updating and retrieving metric values</li></ul><p>In addition, the framework provides the support for retrieving values so that the component does not participate in metric reporting. The component simply creates the metrics it needs, then instruments the component to update the metric whenever its state changes. For example, the component may create a metric that counts the total number of requests received. Then, wherever the component receives a request, a corresponding update to the count is added. Nowhere in the component is any code added to retrieve the count as that is handled by the framework.</p><p>Sinks provide a pluggable interface to hide the specifics of collection systems so that the metrics framework is independent of those dependencies. Sinks:</p><ul><li>Operate independently of other sinks in the system</li><li>Convert metric native values into collection system specific measurements and reports</li><li>Drive the collection and reporting processes</li></ul><p>The third area of the framework is the glue logic, referred to as the <em>MetricsManager</em>. It manages the metrics system for the component. It provides the following:</p><ul><li>Handles framework initialization</li><li>Loads sinks as required</li><li>Manages the list of metrics for the component</li><li>Handles collection and reporting with a set of convenience methods used by sinks</li></ul><p>The framework is designed to be instantiated into a component as part of its process and address space. All objects instantiated as part of the framework are owned by the component and are not shareable with any other component whether local or remote. Any coordination or consistency requirements that may arise in the implementation of a sink shall be the sole responsibility of the sink.</p><h2 id="framework-implementation" tabindex="-1">Framework Implementation <a class="header-anchor" href="#framework-implementation" aria-label="Permalink to &quot;Framework Implementation&quot;">​</a></h2><p>The framework is implemented within jlib. The following sections describe each area of the framework.</p><h3 id="metrics" tabindex="-1">Metrics <a class="header-anchor" href="#metrics" aria-label="Permalink to &quot;Metrics&quot;">​</a></h3><p>Components use metrics to measure their internal state. Metrics can represent everything from the number of requests received to the average length some value remains cached. Components are responsible for creating and updating metrics for each measured state. The framework shall provide a set of metrics designed to cover the majority of component measurement requirements. All metrics share a common interface to allow the framework to manage them in a common way.</p><p>To meet the requirement to manage metrics independent of the underlying metric state, all metrics implement a common interface. All metrics then add their specific methods to update and retrieve internal state. Generally the component uses the update method(s) to update state and the framework uses retrieval methods to get current state when reporting. The metric insures synchronized access.</p><p>For components that already have an implementation that tracks a metric, the framework provides a way to instantiate a custom metric. The custom metric allows the component to leverage the existing implementation and give the framework access to the metric value for collection and reporting. Note that custom metrics only support simple scalar metrics such as a counter or a gauge.</p><h3 id="sinks" tabindex="-1">Sinks <a class="header-anchor" href="#sinks" aria-label="Permalink to &quot;Sinks&quot;">​</a></h3><p>The framework defines a sink interface to support the different requirements of collection systems. Examples of collection systems are Prometheus, Datadog, and Elasticsearch. Each has different requirements for how and when measurements are ingested. The following are examples of different collection system requirements:</p><ul><li>Polled vs Periodic</li><li>Single measurement vs multiple reports</li><li>Report format (JSON, text, etc.)</li><li>Push vs Pull</li></ul><p>Sinks are responsible for two main functions: initiating a collection and reporting measurements to the collection system. The <em>Metrics Reporter</em> provides the support to complete these functions.</p><p>The sink encapsulates all of the collection system requirements providing a pluggable architecture that isolates components from these differences. The framework supports multiple sinks concurrently, each operating independently.</p><p>Instrumented components are not aware of the sink or sinks in use. Sinks can be changed without requiring changes to a component. Therefore, components are independent of the collection system(s) in use.</p><h3 id="metrics-reporter" tabindex="-1">Metrics Reporter <a class="header-anchor" href="#metrics-reporter" aria-label="Permalink to &quot;Metrics Reporter&quot;">​</a></h3><p>The metrics reporter class provides all of the common functions to bind together the component, the metrics it creates, and the sinks to which measurements are reported. It is responsible for the following:</p><ul><li>Initialization of the framework</li><li>Managing the metrics created by the component</li><li>Handling collection and reporting as directed by configured sinks</li></ul><h3 id="metrics-implementations" tabindex="-1">Metrics Implementations <a class="header-anchor" href="#metrics-implementations" aria-label="Permalink to &quot;Metrics Implementations&quot;">​</a></h3><p>The sections that follow discuss metric implementations.</p><h4 id="counter-metric" tabindex="-1">Counter Metric <a class="header-anchor" href="#counter-metric" aria-label="Permalink to &quot;Counter Metric&quot;">​</a></h4><p>A counter metric is a monotonically increasing value that &quot;counts&quot; the total occurrences of some event. Examples include the number of requests received, or the number of cache misses. Once created, the component instruments the code with updates to the count whenever appropriate.</p><h4 id="gauge-metric" tabindex="-1">Gauge Metric <a class="header-anchor" href="#gauge-metric" aria-label="Permalink to &quot;Gauge Metric&quot;">​</a></h4><p>A gauge metric is a continuously updated value representing the current state of an interesting value in the component. For example, the amount of memory used in an internal buffer, or the number of requests waiting on a queue. A gauge metric may increase or decrease in value as needed. Reading the value of a gauge is a stateless operation in that there are no dependencies on the previous reading. The value returned shall always be the current state.</p><p>Once created, the component shall update the gauge anytime the state of what is measured is updated. The metric shall provide methods to increase and decrease the value. The sink reads the value during collection and reporting.</p><h4 id="custom-metric" tabindex="-1">Custom Metric <a class="header-anchor" href="#custom-metric" aria-label="Permalink to &quot;Custom Metric&quot;">​</a></h4><p>A custom metric is a class that allows a component to leverage existing metrics. The component creates an instance of a custom metric (a templated class) and passes a reference to the underlying metric value. When collection is performed, the custom metric simply reads the value of the metric using the reference provided during construction. The component maintains full responsibility for updating the metric value as the custom metric class provides no update methods. The component is also responsible for ensuring atomic access to the value if necessary.</p><h4 id="histogram-metric" tabindex="-1">Histogram Metric <a class="header-anchor" href="#histogram-metric" aria-label="Permalink to &quot;Histogram Metric&quot;">​</a></h4><p>Records counts of measurements according to defined bucket limits. When created, the caller defines as set of bucket limits. During event recording, the component records measurements. The metric separates each recorded measurement into its bucket by testing the measurement value against each bucket limit using a less than or equal test. Each bucket contains a count of measurements meeting that criteria. Additionally, the metric maintains a default bucket for measurements outside of the maximum bucket limit. This is sometimes known as the &quot;inf&quot; bucket.</p><p>Some storage systems, such as Prometheus, require each bucket to accumulate its measurements with the previous bucket(s). It is the responsibility of the sink to accumulate values as needed.</p><h4 id="scaled-histogram-metric" tabindex="-1">Scaled Histogram Metric <a class="header-anchor" href="#scaled-histogram-metric" aria-label="Permalink to &quot;Scaled Histogram Metric&quot;">​</a></h4><p>A histogram metric that allows setting the bucket limit units in one domain, but take measurements in another domain. For example, the bucket limits may represent millisecond durations, yet it is more effecient to use execution cycles to take the measurements. A scaled histogram converts from the the measurement domain (cycles) to the limit units domain using a scale factor provided at initialization. All conversions are encapsulated in the scaled histogram class such that no external scaling is required by any consumer such as a sink.</p><h2 id="configuration" tabindex="-1">Configuration <a class="header-anchor" href="#configuration" aria-label="Permalink to &quot;Configuration&quot;">​</a></h2><p>This section discusses configuration. Since Helm charts are capable of combining configuration data at a global level into a component&#39;s specific configuration, The combined configuration takes the form as shown below. Note that as the design progresses it is expected that there will be additions.</p><div class="language-yaml"><button title="Copy Code" class="copy"></button><span class="lang">yaml</span><pre class="shiki material-theme-palenight"><code><span class="line"><span style="color:#F07178;">component</span><span style="color:#89DDFF;">:</span></span>
<span class="line"><span style="color:#A6ACCD;">      </span><span style="color:#F07178;">metrics</span><span style="color:#89DDFF;">:</span></span>
<span class="line"><span style="color:#A6ACCD;">        </span><span style="color:#F07178;">sinks</span><span style="color:#89DDFF;">:</span></span>
<span class="line"><span style="color:#A6ACCD;">        </span><span style="color:#89DDFF;">-</span><span style="color:#A6ACCD;"> </span><span style="color:#F07178;">type</span><span style="color:#89DDFF;">:</span><span style="color:#A6ACCD;"> </span><span style="color:#C3E88D;">&lt;sink_type&gt;</span></span>
<span class="line"><span style="color:#A6ACCD;">          </span><span style="color:#F07178;">name</span><span style="color:#89DDFF;">:</span><span style="color:#A6ACCD;"> </span><span style="color:#C3E88D;">&lt;sink name&gt;</span></span>
<span class="line"><span style="color:#A6ACCD;">          </span><span style="color:#F07178;">settings</span><span style="color:#89DDFF;">:</span></span>
<span class="line"><span style="color:#A6ACCD;">            </span><span style="color:#F07178;">sink_setting1</span><span style="color:#89DDFF;">:</span><span style="color:#A6ACCD;"> </span><span style="color:#C3E88D;">sink_setting_value1</span></span>
<span class="line"><span style="color:#A6ACCD;">            </span><span style="color:#F07178;">sink_setting2</span><span style="color:#89DDFF;">:</span><span style="color:#A6ACCD;"> </span><span style="color:#C3E88D;">sink_setting_value2</span></span></code></pre></div><p>Where (based on being a child of the current <em>component</em>):</p><p>metrics</p><p>: Metrics configuration for the component</p><p>metrics.sinks</p><p>: List of sinks defined for the component (may have been combined with global config)</p><p>metrics.sinks[].type</p><p>: The type for the sink. The type is substituted into the following pattern to determine the lib to load: libhpccmetrics&lt;type&gt;&lt;shared_object_extension&gt;</p><p>metrics.sinks[].name</p><p>: A name for the sink.</p><p>metrics.sinks[].settings</p><p>: A set of key/value pairs passed to the sink when initialized. It should contain information necessary for the operation of the sink. Nested YML is supported. Example settings are the prometheus server name, or the collection period for a periodic sink.</p><h2 id="metric-naming" tabindex="-1">Metric Naming <a class="header-anchor" href="#metric-naming" aria-label="Permalink to &quot;Metric Naming&quot;">​</a></h2><p>Metric names shall follow a convention as outlined in this section. Because different collection systems have different requirements for how metric value reports are generated, naming is split into two parts.</p><p>First, each metric is given a base name that describes what the underlying value is. Second, meta data is assigned to each metric to further qualify the value. For example, a set of metrics may count the number of requests a component has received. Each metric would have the same base name, but meta data would separate types of request (GET vs POST), or disposition such as pass or fail.</p><h3 id="base-name" tabindex="-1">Base Name <a class="header-anchor" href="#base-name" aria-label="Permalink to &quot;Base Name&quot;">​</a></h3><p>The following convention defines how metric names are formed:</p><ul><li><p>Names consist of parts separated by a period (.)</p></li><li><p>Each part shall use snake case (allows for compound names in each part)</p></li><li><p>Each name shall begin with a prefix representing the scop of the metric</p></li><li><p>Names for metric types shall be named as follows (followed by examples):</p><p>Gauges: &lt;scope&gt;.&lt;plural-noun&gt;.&lt;state&gt; esp.requests.waiting, esp.status_requests.waiting</p><p>Counters: &lt;scope&gt;.&lt;plural-noun&gt;.&lt;past-tense-verb&gt; thor.requests.failed, esp.gateway_requests.queued</p><p>Time: &lt;scope&gt;.&lt;singular-noun&gt;.&lt;state or active-verb&gt;.time dali.request.blocked.time, dali.request.process.time</p></li></ul><h3 id="meta-data" tabindex="-1">Meta Data <a class="header-anchor" href="#meta-data" aria-label="Permalink to &quot;Meta Data&quot;">​</a></h3><p>Meta data further qualifies a metric value. This allows metrics to have the same name, but different scopes or categories. Generally, meta data is only used to furher qualify metrics that would have the same base name, but need further distinction. An example best describes a use case for meta data. Consider a component that accepts HTTP requests, but needs to track GET and POST requests separately. Instead of defining metrics with names <em>post_requests.received</em> and <em>get_requests.received</em>, the component creates two metrics with the base name <em>requests.received</em> and attaches meta data describing the request type of POST to one and GET to the other.</p><p>Use of meta data allows aggregating both types of requests into a single combined count of received requests while allowing a breakdown by type.</p><p>Meta data is represented as a key/value pair and is attached to the metric by the component during metric creation. The sink is responsible for converting meta data into useful information for the collection system during reporting.</p><p>The <em>Component Instrumentation</em> section covers how meta data is added to a metric.</p><h2 id="component-instrumentation" tabindex="-1">Component Instrumentation <a class="header-anchor" href="#component-instrumentation" aria-label="Permalink to &quot;Component Instrumentation&quot;">​</a></h2><p>In order to instrument a component for metrics using the framework, a component must include the metrics header from jlib (<em>jmetrics.hpp</em>) and add jlib as a dependent lib (if not already doing so).</p><p>The general steps for instrumentation are</p><ol><li>Create a metrics reporter object</li><li>Create metric objects for each internal state to measure and add each to the reporter</li><li>Add updates to each metric throughout the component wherever metric state changes</li></ol><p>The <em>metrics reporter</em> is a singleton created using the platform defined singleton pattern template. The component must obtain a reference to the reporter. Use the following example:</p><div class="language-cpp"><button title="Copy Code" class="copy"></button><span class="lang">cpp</span><pre class="shiki material-theme-palenight"><code><span class="line"><span style="color:#F78C6C;">using</span><span style="color:#A6ACCD;"> </span><span style="color:#C792EA;">namespace</span><span style="color:#A6ACCD;"> </span><span style="color:#FFCB6B;">hpccMetrics</span><span style="color:#89DDFF;">;</span></span>
<span class="line"><span style="color:#A6ACCD;">MetricsManager </span><span style="color:#89DDFF;">&amp;</span><span style="color:#A6ACCD;">metricsManager </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#82AAFF;">queryMetricsManager</span><span style="color:#89DDFF;">();</span></span></code></pre></div><p>Metrics are wrapped by a standard C++ shared pointer. The component is responsible for maintaining a reference to each shared pointer during the lifetime of the metric. The framework keeps a weak pointer to each metric and thus does not maintain a reference. The following is an example of creating a counter metric and adding it to the reporter. The <em>using namespace</em> eliminates the need to prefix all metrics types with <em>hpccMetrics</em>. Its use is assumed for all code examples that follow.</p><div class="language-cpp"><button title="Copy Code" class="copy"></button><span class="lang">cpp</span><pre class="shiki material-theme-palenight"><code><span class="line"><span style="color:#FFCB6B;">std</span><span style="color:#89DDFF;">::</span><span style="color:#A6ACCD;">shared_ptr</span><span style="color:#89DDFF;">&lt;</span><span style="color:#A6ACCD;">CounterMetric</span><span style="color:#89DDFF;">&gt;</span><span style="color:#A6ACCD;"> pCounter </span><span style="color:#89DDFF;">=</span><span style="color:#A6ACCD;"> </span><span style="color:#FFCB6B;">std</span><span style="color:#89DDFF;">::</span><span style="color:#82AAFF;">make_shared</span><span style="color:#89DDFF;">&lt;</span><span style="color:#FFCB6B;">CounterMetric</span><span style="color:#89DDFF;">&gt;(</span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">metricName</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">description</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">);</span></span>
<span class="line"><span style="color:#A6ACCD;">metricsManager</span><span style="color:#89DDFF;">.</span><span style="color:#82AAFF;">add</span><span style="color:#89DDFF;">(</span><span style="color:#A6ACCD;">pCounter</span><span style="color:#89DDFF;">);</span></span></code></pre></div><p>Note the metric type for both the shared pointer variable and in the <em>make_shared</em> template that creates the metric and returns a shared pointer. Simply substitute other metric types and handle any differences in the constructor arguments as needed.</p><p>Once created, add updates to the metric state throughout the component code where required. Using the above example, the following line of code increments the counter metric by 1.</p><div class="language-cpp"><button title="Copy Code" class="copy"></button><span class="lang">cpp</span><pre class="shiki material-theme-palenight"><code><span class="line"><span style="color:#A6ACCD;">pCounter</span><span style="color:#89DDFF;">-&gt;</span><span style="color:#82AAFF;">inc</span><span style="color:#89DDFF;">(</span><span style="color:#F78C6C;">1</span><span style="color:#89DDFF;">);</span></span></code></pre></div><p>Note that only a single line of code is required to update the metric.</p><p>That&#39;s it! There are no component requirements related to collection or reporting of metric values. That is handled by the framework and loaded sinks.</p><p>For convenience, there are function templates that handle creating the reporter, creating a metric, and adding the metric to the reporter. For example, the above three lines of code that created the reporter, a metric, and added it, can be replaced by the following:</p><pre><code>auto pCount = createMetricAndAddToManager&lt;CounterMetric&gt;(&quot;metricName&quot;, &quot;description&quot;);
</code></pre><p>For convenience a similar function template exists for creating custom metrics. For a custom metric the framework must know the metric type and have a reference to the underlying state variable. The following template function handles creating a custom metric and adding it to the reporter (which is created if needed as well):</p><pre><code>auto pCustomMetric = createCustomMetricAndAddToManager(&quot;customName&quot;, &quot;description&quot;, metricType, value);
</code></pre><p>Where:</p><ul><li><p>metricType</p><p>A defined metric type as defined by the <em>MetricType</em> enum.</p></li><li><p>value</p><p>A reference to the underlying event state which must be a scalar value convertable to a 64bit unsigned integer (__uint64)</p></li></ul><h3 id="adding-metric-meta-data" tabindex="-1">Adding Metric Meta Data <a class="header-anchor" href="#adding-metric-meta-data" aria-label="Permalink to &quot;Adding Metric Meta Data&quot;">​</a></h3><p>A component, depending on requirements, may attach meta data to further qualify created metrics. Meta data takes the form of key value pairs. The base metric class <em>MetricBase</em> constructor defines a parameter for a vector of meta data. Metric subclasses also define meta data as a constructor parameter, however an empty vector is the default. The <em>IMetric</em> interface defines a method for retrieving the meta data.</p><p>Meta data is order dependent.</p><p>Below are two examples of constructing a metric with meta data. One creates the vector and passes it as a parameter, the other constructs the vector in place.</p><div class="language-cpp"><button title="Copy Code" class="copy"></button><span class="lang">cpp</span><pre class="shiki material-theme-palenight"><code><span class="line"><span style="color:#A6ACCD;">MetricMetaData metaData1</span><span style="color:#89DDFF;">{{</span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">key1</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">,</span><span style="color:#F07178;"> </span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">value1</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">}};</span></span>
<span class="line"><span style="color:#FFCB6B;">std</span><span style="color:#89DDFF;">::</span><span style="color:#A6ACCD;">shared_ptr</span><span style="color:#89DDFF;">&lt;</span><span style="color:#A6ACCD;">CounterMetric</span><span style="color:#89DDFF;">&gt;</span><span style="color:#A6ACCD;"> pCounter1 </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#FFCB6B;">std</span><span style="color:#89DDFF;">::</span><span style="color:#82AAFF;">make_shared</span><span style="color:#89DDFF;">&lt;</span><span style="color:#FFCB6B;">CounterMetric</span><span style="color:#89DDFF;">&gt;(</span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">requests.completed</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">description</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> SMeasureCount</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> metaData1</span><span style="color:#89DDFF;">);</span></span>
<span class="line"></span>
<span class="line"><span style="color:#FFCB6B;">std</span><span style="color:#89DDFF;">::</span><span style="color:#A6ACCD;">shared_ptr</span><span style="color:#89DDFF;">&lt;</span><span style="color:#A6ACCD;">CounterMetric</span><span style="color:#89DDFF;">&gt;</span><span style="color:#A6ACCD;"> pCounter2 </span><span style="color:#89DDFF;">=</span></span>
<span class="line"><span style="color:#A6ACCD;">    </span><span style="color:#FFCB6B;">std</span><span style="color:#89DDFF;">::</span><span style="color:#82AAFF;">make_shared</span><span style="color:#89DDFF;">&lt;</span><span style="color:#FFCB6B;">CounterMetric</span><span style="color:#89DDFF;">&gt;(</span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">requests.completed</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">description</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> SMeasureCount</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> MetricMetaData{{</span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">key1</span><span style="color:#89DDFF;">&quot;</span><span style="color:#89DDFF;">,</span><span style="color:#A6ACCD;"> </span><span style="color:#89DDFF;">&quot;</span><span style="color:#C3E88D;">value2</span><span style="color:#89DDFF;">&quot;</span><span style="color:#A6ACCD;">}}</span><span style="color:#89DDFF;">);</span></span></code></pre></div><h3 id="metric-units" tabindex="-1">Metric Units <a class="header-anchor" href="#metric-units" aria-label="Permalink to &quot;Metric Units&quot;">​</a></h3><p>Metric units are treated separately from the base name and meta data. The reason is to allow the sink to translate based on collection system requirements. The base framework provides a convenience method for converting units into a string. However, the sink is free to do any conversions, both actual units and the string representation, as needed.</p><p>Metric units are defined using a subset of the <em>StaticsMeasure</em> enumeration values defined in <strong>jstatscodes.h</strong>. The current values are used:</p><ul><li>SMeasureTimeNs - A time measurement in nanoseconds</li><li>SMeasureCount - A count of events</li><li>SMeasureSize - Size in bytes</li></ul>`,132),r=[o];function i(l,c,p,m,h,d){return t(),a("div",null,r)}const g=e(n,[["render",i]]);export{f as __pageData,g as default};
