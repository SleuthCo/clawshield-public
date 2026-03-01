---
framework: "Research Visualization & Analytical Display"
version: "1.0"
domain: "Research Synthesis"
agent: "coda"
tags: ["visualization", "timeline", "geospatial", "entity-relationship", "evidence-matrix", "confidence-mapping"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

## Analytical Visualization Principles

Visualization in research and investigation serves a fundamentally different purpose from presentation graphics. Analytical visualizations are thinking tools — they reveal patterns, expose gaps, and support reasoning. They are not primarily for communication (though they can serve that purpose secondarily).

**Edward Tufte's principles**: Maximize the data-ink ratio (every element should convey information). Minimize chart junk (decorative elements that do not carry data). Use small multiples (multiple small charts showing the same structure across different conditions for comparison). Show the data at multiple levels of detail (overview, zoom, and filter). Never distort the data through misleading scales, truncated axes, or inappropriate chart types.

**Jacques Bertin's visual variables**: Position (most effective for quantitative comparison), size (good for quantitative comparison but less precise), shape (good for categorical distinction), color hue (good for categorical distinction — limit to 7-12 distinguishable categories), color value/saturation (good for sequential quantitative data), and orientation (limited use). Choose variables based on the data type and the analytical question.

**Analytical vs. presentation visualization**: Analytical visualizations are for the analyst during the investigation — they should be information-dense, interactive, and exploratory. Presentation visualizations are for the consumer in the final report — they should be clear, focused, and communicate a specific point. Do not confuse the two — an exploratory visualization that reveals patterns to the analyst may overwhelm a consumer who needs a simple message.

**The visual thinking process**: Generate multiple candidate visualizations. Evaluate each for the patterns it reveals. Iterate — modify, combine, or discard visualizations as understanding develops. The act of creating visualizations forces explicit thinking about relationships, sequences, and categories that may remain implicit in text-based analysis.

## Timeline Reconstruction

Timelines are fundamental analytical tools for establishing sequences, identifying temporal patterns, and understanding the chronology of events.

**Constructing analytical timelines**: Plot events chronologically with precise dates and times where available. Use consistent granularity (if some events are dated to the hour and others to the month, indicate the precision of each). Include multiple tracks or swim lanes for different actors, themes, or data sources. Color-code events by category, source, or confidence level.

**Multi-track timelines**: Use parallel tracks to show the activities of different entities simultaneously. Vertical alignment reveals temporal coincidences (events happening at the same time). Gaps in tracks reveal periods of unknown activity. The juxtaposition of multiple tracks often reveals relationships that are invisible when examining each entity's history separately.

**Event sequence analysis**: Beyond simple chronology, analyze: temporal clustering (are events concentrated in specific periods?), periodicity (do events recur at regular intervals?), acceleration or deceleration (is the pace of events changing?), and temporal proximity to other events (does event A consistently precede event B?). These patterns can suggest causal relationships, coordination, or behavioral patterns.

**Timeline sources and confidence**: Not all events on a timeline are equally certain. Indicate the source and confidence level for each event. Distinguish between: confirmed events (multiple independent sources), reported events (single source, unconfirmed), estimated events (date/time is approximate), and inferred events (deduced from other evidence rather than directly observed).

**Tools for timeline construction**: Dedicated timeline tools (TimelineJS, Tiki-Toki, Aeon Timeline), project management tools adapted for analysis (Microsoft Project, Gantt charts), spreadsheet-based timelines, and specialized investigative tools (i2 Analyst's Notebook, Palantir). For complex investigations, use tools that support multi-track, multi-layer timelines with filtering and zooming capabilities.

## Geospatial Analysis and Mapping

Geospatial analysis examines the spatial dimension of events, relationships, and patterns. Location data adds a powerful analytical dimension that can reveal patterns invisible in non-spatial data.

**Point mapping**: Plot individual events, entities, or observations on a map. Cluster analysis reveals geographic concentrations. Outlier identification reveals anomalous locations. Time-animated point maps show movement patterns and spatial evolution of events.

**Heat maps and density analysis**: Kernel density estimation shows where events are concentrated, revealing "hot spots" even when individual points overlap. Useful for: crime pattern analysis, communication hub identification, activity concentration mapping, and resource allocation planning.

**Connection mapping**: Draw lines between locations that are connected by relationships (communications, travel, transactions). Connection maps reveal: hub-and-spoke patterns (central locations connected to many others), corridor patterns (travel or communication routes), and network structure overlaid on geography.

**Territory and boundary analysis**: Map the geographic extent of influence, operation, or control. Identify contested areas, buffer zones, and gaps. Overlay multiple territorial maps to identify conflicts and opportunities.

**Movement analysis**: Track the movement of entities over time. Analyze: patterns of movement (regular routes, anomalous deviations), speed and timing (are movements consistent with stated purposes?), co-location (do different entities appear in the same locations at the same times?), and avoidance (do entities systematically avoid certain areas?).

**Geospatial data sources**: GPS data from devices and applications, cell tower connection records, social media geotags, satellite imagery, address records, travel documents, vehicle tracking, and open geographic databases (OpenStreetMap, Natural Earth). Each source has different accuracy, coverage, and temporal resolution.

**Geospatial tools**: QGIS (free, open-source GIS), ArcGIS (commercial, comprehensive), Google Earth Pro (free, good for basic analysis and visualization), Kepler.gl (web-based, good for large point datasets), and programming libraries (Leaflet, Mapbox, GeoPandas).

## Entity Relationship Diagrams

Entity relationship diagrams (ERDs) visualize the connections between people, organizations, accounts, assets, events, and other entities. They are the primary visualization tool for link analysis.

**Entity types and attributes**: Define entity categories with distinct visual representations (icons, shapes, colors). Common entity types: person, organization, address, phone number, email, bank account, vehicle, event, document. Each entity has attributes (name, date of birth, registration number, etc.) that can be displayed on hover or in detail panels.

**Relationship types**: Define relationship categories with distinct visual representations (line style, color, label). Common relationship types: personal (family, friend, associate), professional (employer, colleague, business partner), financial (transaction, shared account, beneficial ownership), communication (phone call, email, meeting), and inferred (co-location, shared attribute). Label relationships with specific information (date, amount, frequency).

**Layout strategies**: Force-directed layout (connected entities attract, unconnected entities repel — reveals clusters and bridges). Hierarchical layout (shows command structures, organizational hierarchies, corporate ownership chains). Circular layout (places entities in a circle to emphasize connections between them). Manual layout (analyst arranges entities to tell a specific story or highlight specific relationships).

**Managing complexity**: Large entity relationship diagrams become unreadable. Strategies: filtering (show only entities and relationships meeting specified criteria), aggregation (collapse subsidiaries into parent organizations, or group entities by category), layering (show different relationship types on different layers that can be toggled), and subnetwork extraction (analyze specific clusters separately before examining the full network).

**Building ERDs incrementally**: Start with known entities and confirmed relationships. Add entities and relationships as they are discovered. Use different line styles to distinguish confirmed, probable, and possible relationships. Maintain a log of when each entity and relationship was added and what evidence supports it.

## Evidence Matrices

Evidence matrices systematically organize evidence against hypotheses, criteria, or themes. They are the primary tool for structured analytical comparison.

**ACH matrix**: Hypotheses as columns, evidence items as rows. Cell values indicate consistency (C), inconsistency (I), or not applicable (NA). Highlight inconsistencies — the hypothesis with the fewest inconsistencies is favored. Color-code cells for rapid visual assessment.

**Cross-case comparison matrix**: Cases as rows, attributes or characteristics as columns. Enables systematic comparison across cases to identify patterns, outliers, and common features. Used in qualitative comparative analysis, competitive benchmarking, and pattern identification.

**Source-evidence matrix**: Sources as rows, key questions or claims as columns. Cell values indicate what each source says about each question. Reveals: corroboration (multiple sources supporting the same claim), contradiction (sources disagreeing), and gaps (questions that no source addresses).

**Joint display for mixed methods**: Quantitative findings in one column, qualitative findings in another, with a third column for integrated interpretation. This format makes explicit how quantitative and qualitative data converge, diverge, or complement each other.

**Constructing effective matrices**: Define rows and columns clearly before populating. Use consistent coding or rating scales across cells. Include a legend. Allow for "unknown" or "not assessed" entries — do not force assessments when information is insufficient. Review completed matrices for patterns: full rows suggest well-assessed items; empty rows suggest data gaps; full columns suggest well-addressed hypotheses; empty columns suggest unsupported hypotheses.

## Confidence Mapping

Confidence mapping visualizes the analyst's certainty across different aspects of the assessment, making uncertainty explicit and spatial.

**Confidence heat maps**: Overlay confidence levels on geographic maps (where are we most and least certain about what is happening?), on timelines (when are we most and least certain?), or on organizational charts (which relationships are confirmed vs. inferred?). Color gradients (green-yellow-red or similar) provide intuitive confidence visualization.

**Evidence sufficiency maps**: For each key judgment or hypothesis, map the evidence landscape: where is evidence abundant and strong, where is it sparse or weak, and where does it not exist at all? This visualization guides collection prioritization — focus on filling the gaps that matter most for the analytical question.

**Assumption vulnerability mapping**: Identify the key assumptions underlying the assessment and map their vulnerability. Highly vulnerable assumptions (unsupported, critical to the conclusion) are high-priority risks. Well-supported, non-critical assumptions are low-priority. This visual prioritization helps focus assumption-testing efforts.

**Analytical confidence dashboard**: A summary visualization for the overall assessment showing: the key judgment, the confidence level, the primary supporting evidence, the most significant counter-evidence, the most vulnerable assumptions, and the most important intelligence gaps. This dashboard provides a one-page overview of the analytical health of the assessment.

## Visualization Best Practices for Investigations

**Annotation and provenance**: Every element in an analytical visualization should be traceable to its source. Annotate events with source references. Include confidence indicators on all entities and relationships. Maintain a separate evidence log that documents the support for each visual element.

**Temporal versioning**: Save versions of analytical visualizations at key points in the investigation. This creates an audit trail showing how the analytical picture evolved as new information was obtained. Versioning also supports retrospective analysis of the investigation process — what did we know when, and how did our understanding change?

**Avoiding misleading visualizations**: Do not use 3D effects that distort perception. Do not truncate axes to exaggerate differences. Do not use bubble charts where area comparisons are ambiguous. Do not use rainbow color scales (they create artificial boundaries in continuous data). Do not present inferred relationships with the same visual weight as confirmed relationships.

**Interactive vs. static visualizations**: Interactive visualizations (filtering, zooming, drilling down, hovering for details) are powerful for analysis but require appropriate tools and training. Static visualizations (for reports, briefings, and archival) must stand alone without interaction — they need clear titles, labels, legends, and annotations.

**Visualization literacy**: Not all consumers are fluent in reading complex visualizations. For expert audiences, use sophisticated analytical displays. For general audiences, use simpler formats with explanatory annotations. Always include a brief text description of the key insight the visualization conveys — do not require the reader to discover it independently.

## Integrating Multiple Visualization Types

Complex investigations require multiple visualization types used in coordination.

**The analysis workspace**: Maintain a coordinated set of visualizations — timeline, network diagram, geographic map, and evidence matrix — that are linked. Selecting an entity in one view highlights it in all others. This multi-view approach enables the analyst to examine the same data from multiple perspectives simultaneously.

**Visualization sequences in reports**: In written reports, sequence visualizations to tell an analytical story. Start with an overview visualization (the big picture), then zoom into specific areas of interest, then show detail visualizations that support specific analytical points. Each visualization should build on the previous one, progressively adding detail and analytical depth.

**Layering information**: Build complex pictures through layered addition rather than presenting everything at once. Start with the basic structure, then add temporal information, then add confidence levels, then add specific details. Each layer adds value without overwhelming the viewer.
