---
framework: "Link and Network Analysis"
version: "1.0"
domain: "Investigative Analysis"
agent: "coda"
tags: ["network-analysis", "graph-theory", "social-network", "entity-resolution", "maltego", "relationship-mapping"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

## Network Analysis Fundamentals

Network analysis studies the structure and dynamics of relationships between entities. A network (or graph) consists of nodes (vertices) representing entities and edges (links) representing relationships between them. Network analysis reveals patterns invisible in tabular data — it shows who is connected to whom, how information or resources flow, and which entities occupy structurally important positions.

**Network types**: Undirected networks have symmetric relationships (friendship, co-membership). Directed networks have asymmetric relationships (email sender-receiver, command hierarchy). Weighted networks assign values to edges (frequency of communication, transaction amounts). Bipartite networks have two types of nodes (people and organizations, authors and papers). Multiplex networks have multiple types of edges between the same nodes (professional and personal relationships). Temporal networks capture how relationships change over time.

**Network representation**: Adjacency matrices (N x N matrix where entry [i,j] indicates a connection between nodes i and j). Edge lists (each row is a pair of connected nodes, optionally with attributes). Adjacency lists (for each node, list its neighbors). For large sparse networks, edge lists and adjacency lists are more memory-efficient than matrices.

**Data sources for network construction**: Communication records (email, phone, messaging), financial transactions, social media connections and interactions, co-authorship or co-citation, organizational charts, event attendance, travel records, legal documents (contracts, filings, corporate records), and surveillance data. Each source captures a different dimension of relationships — combining sources creates a richer picture.

## Graph Theory for Investigations

Graph theory provides the mathematical foundation for understanding network structure and identifying significant patterns.

**Degree centrality**: The number of connections a node has. In directed networks, distinguish in-degree (incoming connections) and out-degree (outgoing connections). High-degree nodes are "hubs" — well-connected entities that may be central to communication, resource flow, or organizational structure. Degree distribution reveals the overall connectivity pattern of the network.

**Betweenness centrality**: The proportion of shortest paths between all pairs of nodes that pass through a given node. High-betweenness nodes are "brokers" — they bridge different parts of the network and control information flow between otherwise disconnected groups. Removing a high-betweenness node can fragment the network into isolated components. In investigations, brokers are often key facilitators, intermediaries, or gatekeepers.

**Closeness centrality**: The inverse of the average shortest path length from a node to all other nodes. High-closeness nodes can reach the entire network quickly — they are well-positioned for rapid information dissemination or efficient coordination. In investigations, these nodes may be operational coordinators.

**Eigenvector centrality**: A node's centrality is proportional to the sum of its neighbors' centralities. Being connected to well-connected nodes matters more than simply having many connections. Google's PageRank algorithm is a variant of eigenvector centrality. In investigations, high eigenvector centrality identifies nodes connected to other important nodes — potential leaders or influencers even if they have few direct connections.

**Clustering coefficient**: Measures the density of connections among a node's neighbors. A high clustering coefficient indicates a tightly knit group where "friends of friends are friends." Low clustering with high betweenness suggests a node that bridges separate groups. Clustering reveals cliques, cells, or tightly coordinated subgroups within a larger network.

**Community detection**: Algorithms that identify densely connected subgroups within the network. Methods include modularity optimization (Louvain, Leiden algorithms), label propagation, spectral clustering, and stochastic block models. Communities may represent organizational units, operational cells, social circles, or collaborative groups. Overlapping community detection identifies nodes that belong to multiple groups — potential boundary spanners or dual-role individuals.

**Shortest paths and geodesic distance**: The minimum number of edges between two nodes. Identifies the most efficient communication or influence pathways. In investigations, shortest paths reveal how information or resources could flow between entities of interest. Average path length characterizes how "small" the network is.

## Social Network Analysis

Social Network Analysis (SNA) applies network science specifically to human social relationships, combining structural analysis with social theory.

**Structural holes** (Burt): Gaps in the social structure where non-redundant contacts on either side of the gap have access to different information and resources. Individuals who span structural holes ("brokers") gain information advantages, control benefits, and are positioned for creative recombination of ideas from different groups. In investigations, structural hole positions often indicate intermediary or coordinating roles.

**Strength of weak ties** (Granovetter): Weak ties (acquaintances) often provide more novel information than strong ties (close friends) because they bridge different social circles. In investigations, weak ties may be the channels through which sensitive information, opportunities, or recruitment flows between otherwise separate groups.

**Network closure and trust**: Dense, closed networks (where everyone knows everyone) facilitate trust, norms, and cooperation — but also groupthink and insularity. In investigation contexts, closed networks indicate high-trust groups that may be more secretive and harder to penetrate but also more cohesive in their operations.

**Key player identification**: Borgatti's key player problem formalizes two network optimization problems: KPP-Neg (removing nodes to maximally disrupt the network — identifying targets for disruption) and KPP-Pos (selecting nodes to maximally reach the entire network — identifying targets for information dissemination). These algorithms go beyond simple centrality metrics to find optimal sets of nodes.

**Ego network analysis**: Analyze the network from a single individual's perspective. The ego (focal individual) is at the center; alters (contacts) form the surrounding network. Analyze: ego's degree, density among alters, presence of structural holes, and the composition of the ego network (types of alters, strength of ties). Useful when full network data is unavailable or when focusing on a specific person of interest.

## Maltego-Style Investigation Workflows

Maltego and similar link-analysis tools (i2 Analyst's Notebook, Palantir, Gephi) support visual investigation through entity-relationship mapping.

**Entity-based investigation**: Start with a seed entity (person, organization, domain, IP address, phone number, email). Use transforms (automated queries to data sources) to discover related entities and relationships. Pivot from each new entity to discover further connections. The investigation expands outward from the seed, building a web of relationships.

**Common investigation pivots**:
- Person to organization: Employment records, corporate filings, LinkedIn profiles
- Person to person: Communication records, social media connections, shared addresses, co-employment
- Organization to organization: Shared directors, business relationships, co-investment, supply chain
- Domain to IP: DNS resolution, hosting infrastructure
- IP to domain: Reverse DNS, virtual hosting
- Email to person: WHOIS, social media accounts, data breach records
- Phone to person: Carrier records, reverse lookup, social media accounts

**Visual analysis techniques**: Arrange the graph to reveal structure. Force-directed layouts position connected nodes closer together, revealing clusters. Hierarchical layouts show command structures. Timeline layouts show temporal sequences. Geospatial layouts show geographic relationships. Use node size to represent centrality, edge thickness to represent weight, and color to represent categories or group membership.

**Investigation workflow**: (1) Define the intelligence requirement — what do you need to know? (2) Identify seed entities from available information. (3) Systematically expand the graph through transforms and manual research. (4) Periodically pause expansion to analyze the emerging structure. (5) Identify key nodes, clusters, and pathways. (6) Validate findings through independent sources. (7) Document the investigation trail for reproducibility and legal admissibility.

## Entity Resolution

Entity resolution (also called record linkage, deduplication, or data matching) is the process of determining when different data records refer to the same real-world entity.

**The challenge**: The same person may appear across databases with different name spellings, addresses, phone numbers, and identifiers. Organizations may use trade names, abbreviations, or subsidiaries. Without resolution, analysis is fragmented across disconnected records representing the same entity.

**Deterministic matching**: Exact or rule-based matching on key fields (e.g., Social Security Number, passport number, company registration number). Fast and precise but misses records with errors or missing identifiers. Use as a first pass.

**Probabilistic matching**: The Fellegi-Sunter model assigns weights to field agreements and disagreements based on their discriminating power. Fields that rarely match by coincidence (e.g., date of birth) contribute more weight than common fields (e.g., gender). Records above a threshold are considered matches; records in the ambiguous zone require manual review.

**String similarity methods**: Exact matching misses variations. Use approximate matching: Levenshtein distance (edit distance — number of insertions, deletions, substitutions), Jaro-Winkler (weights early character matches — good for names), Soundex/Metaphone (phonetic encoding — matches names that sound alike), and n-gram similarity (compares character subsequences). For addresses, use standardization and geocoding before matching.

**Machine learning approaches**: Train classifiers on labeled match/non-match pairs. Features include field-level similarity scores, frequency-based features (rare names are more discriminating), and contextual features. Random forest, gradient boosting, and deep learning models can capture complex matching patterns. Active learning minimizes labeling effort by focusing on the most informative cases.

**Blocking and indexing**: Comparing every record pair is computationally infeasible for large datasets (n^2 comparisons). Blocking reduces comparisons by only comparing records that share a key attribute (e.g., same first initial and zip code). Sorted neighborhood (sliding window over sorted records) and locality-sensitive hashing are scalable alternatives.

## Relationship Mapping and Visualization

Effective visualization transforms complex network data into actionable intelligence.

**Relationship types to map**: Direct relationships (A knows B, A pays B), indirect relationships (A and B share an address, organization, or event), temporal relationships (A contacted B on specific dates), and inferred relationships (A and B exhibit correlated behavior patterns).

**Link chart construction**: Place entities as nodes with type-specific icons (person, organization, vehicle, address, account). Draw edges for confirmed relationships with labels describing the relationship type and evidence. Use line style to indicate confidence: solid for confirmed, dashed for suspected, dotted for inferred. Annotate with dates, amounts, and other contextual information.

**Timeline analysis**: Plot events and communications chronologically. Identify: temporal clustering (bursts of activity that may indicate operations or responses to events), regular patterns (scheduled meetings, recurring transactions), and anomalies (unusual timing or frequency). Timelines are essential for understanding the sequence of events and establishing temporal proximity (necessary but not sufficient for causal inference).

**Geographic analysis**: Plot entities and events on maps. Identify spatial clustering, movement patterns, co-location, and geographic relationships between entities. Use heat maps for density analysis and connection maps for relationship flows. Geospatial analysis is particularly valuable for: identifying meeting locations, understanding territorial patterns, and correlating events with locations.

**Matrix analysis**: Association matrices cross-tabulate entities against attributes, events, or other entities. Binary matrices indicate presence/absence; weighted matrices indicate frequency or strength. Rearranging rows and columns can reveal clusters and patterns. Matrices are particularly useful for systematically identifying co-occurrences (e.g., which people attended the same events).

## Advanced Network Analysis Techniques

Beyond basic metrics, advanced techniques reveal deeper structural patterns.

**Temporal network analysis**: Many real-world networks change over time. Analyze: how the network evolves (growth, decay, restructuring), how individual nodes' positions change, and how dynamic processes (information flow, contagion) play out over the temporal network. Snapshot-based analysis examines the network at discrete time points; event-based analysis treats each interaction as a timestamped event.

**Motif analysis**: Network motifs are small, recurring subgraph patterns that occur more frequently than expected by chance. In social networks, certain triadic configurations (e.g., transitive triads where friends of friends become friends) are overrepresented. In organizational networks, specific patterns may indicate hierarchy, information brokerage, or operational cells. Motif frequencies serve as a "fingerprint" of network structure.

**Network resilience analysis**: How robust is the network to node or edge removal? Targeted removal of high-centrality nodes (attacks) versus random removal (failures) have different effects. Analyze: what is the minimum set of nodes whose removal disconnects the network? Which nodes' removal maximally reduces network efficiency? This analysis identifies critical vulnerabilities and informs disruption strategies.

**Bipartite projection**: Bipartite networks (e.g., people and events) can be projected onto one mode to create a unipartite network (e.g., people connected by shared event attendance). Projection can reveal hidden relationships but also creates false positives — two people attending the same large event may have no actual connection. Weight projected edges by the specificity of shared affiliations (smaller, more exclusive events are stronger indicators).

**Dynamic community detection**: Track how communities form, grow, merge, split, and dissolve over time. Identify: stable core members, peripheral members who come and go, and structural shifts that may indicate organizational changes. Methods include temporal extensions of modularity optimization and evolutionary clustering.

## Practical Investigation Considerations

**Starting an investigation**: Begin with what you know (seed entities and relationships). Build a preliminary hypothesis about the structure you expect to find. Use the hypothesis to guide data collection and analysis, but remain open to surprises. Document every data source, analytical decision, and interpretation.

**Managing complexity**: Large networks become visually uninterpretable. Use filtering (show only nodes above a centrality threshold), aggregation (collapse subsidiaries into parent organizations), and decomposition (analyze communities separately before examining inter-community connections). Focus on the subnetwork relevant to the specific intelligence question.

**Avoiding analytical pitfalls**: Absence of a link is not evidence of no relationship — it may reflect incomplete data. High centrality does not imply guilt or importance — it may reflect a structural role. Correlation in network behavior does not imply coordination — similar environments produce similar behavior. Always seek corroborating evidence before drawing conclusions from network structure alone.

**Evidence standards**: Network analysis produces analytical judgments, not proof. Document the data sources, methods, assumptions, and confidence levels for every finding. Distinguish between confirmed relationships (direct evidence), inferred relationships (structural analysis), and hypothesized relationships (analytical judgment). Present alternative interpretations of the network structure.
