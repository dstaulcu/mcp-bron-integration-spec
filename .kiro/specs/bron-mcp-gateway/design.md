# Design Document: BRON MCP Gateway

## Overview

The BRON MCP Gateway is an MCP (Model Context Protocol) server that exposes the BRON (Bridging Reconnaissance and Operational Nexus) cybersecurity knowledge graph to AI assistants and other MCP clients. BRON connects multiple cybersecurity datasets—CVEs, CWEs, MITRE ATT&CK techniques, and CAPEC attack patterns—into a unified graph database, enabling comprehensive threat intelligence analysis.

This design implements a Python-based MCP server using the official MCP SDK, backed by ArangoDB as the graph database. The server exposes BRON's capabilities through three MCP primitives:

- **Tools**: Query and search operations (query_cve, query_cwe, query_attack_technique, query_capec, find_relationships, search_bron, data management tools)
- **Resources**: Direct entity access via URIs (bron://cve/{id}, bron://cwe/{id}, etc.)
- **Prompts**: Pre-defined analysis templates (analyze_threat, discover_attack_path)

The architecture supports three deployment scenarios:
1. **Cloud/Internet-connected**: Automated data updates from upstream sources
2. **On-premises with internet**: Manual or scheduled updates
3. **Isolated networks**: Pre-loaded data with export/import synchronization for non-internet connected environments

### Key Design Decisions

**MCP SDK Selection**: Use the official Python MCP SDK (`mcp` package) for protocol compliance and maintainability. This ensures compatibility with standard MCP clients like Claude Desktop.

**Graph Database**: ArangoDB provides native graph traversal capabilities essential for relationship queries across CVE→CWE→CAPEC→ATT&CK chains. Its multi-model design (document + graph) efficiently handles both entity storage and relationship traversal.

**Containerization**: Docker Compose orchestrates the MCP server and ArangoDB, simplifying deployment across all three scenarios. A single image supports all deployment modes via runtime flags.

**Data Pipeline**: Separate the data ingestion layer from the MCP server layer. The build process downloads and transforms upstream data (NVD, MITRE, CAPEC) into ArangoDB collections, while the MCP server provides read-only query access.

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                        MCP Client                            │
│                  (Claude Desktop, etc.)                      │
└────────────────────────┬────────────────────────────────────┘
                         │ MCP Protocol (stdio/SSE)
                         │
┌────────────────────────▼────────────────────────────────────┐
│                   BRON MCP Server                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           MCP Protocol Handler                       │   │
│  │  - initialize, tools/list, resources/list, etc.     │   │
│  └──────────────────┬───────────────────────────────────┘   │
│                     │                                        │
│  ┌──────────────────▼───────────────────────────────────┐   │
│  │              Tool Handlers                           │   │
│  │  - query_cve, query_cwe, query_attack_technique     │   │
│  │  - query_capec, find_relationships, search_bron     │   │
│  │  - get_data_version, update/export/import tools     │   │
│  └──────────────────┬───────────────────────────────────┘   │
│                     │                                        │
│  ┌──────────────────▼───────────────────────────────────┐   │
│  │         Resource & Prompt Handlers                   │   │
│  │  - bron:// URI resolution                           │   │
│  │  - analyze_threat, discover_attack_path prompts     │   │
│  └──────────────────┬───────────────────────────────────┘   │
│                     │                                        │
│  ┌──────────────────▼───────────────────────────────────┐   │
│  │           BRON Query Layer                           │   │
│  │  - Entity retrieval, relationship traversal         │   │
│  │  - Full-text search, graph path finding             │   │
│  └──────────────────┬───────────────────────────────────┘   │
└────────────────────┬┼───────────────────────────────────────┘
                     ││ ArangoDB Driver (python-arango)
                     ││
┌────────────────────▼▼───────────────────────────────────────┐
│                      ArangoDB                                │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Collections:                                        │   │
│  │  - cves (CVE documents)                             │   │
│  │  - cwes (CWE documents)                             │   │
│  │  - attack_techniques (ATT&CK documents)             │   │
│  │  - capec_patterns (CAPEC documents)                 │   │
│  │                                                      │   │
│  │  Edge Collections:                                   │   │
│  │  - cve_to_cwe, cwe_to_capec, capec_to_attack       │   │
│  │  - attack_to_cve (bidirectional relationships)      │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                  Data Build Pipeline                         │
│                  (Separate Process)                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Data Fetchers:                                      │   │
│  │  - NVD API (CVE data)                               │   │
│  │  - MITRE ATT&CK STIX (techniques)                   │   │
│  │  - MITRE CWE XML (weaknesses)                       │   │
│  │  - CAPEC XML (attack patterns)                      │   │
│  └──────────────────┬───────────────────────────────────┘   │
│                     │                                        │
│  ┌──────────────────▼───────────────────────────────────┐   │
│  │  Data Transformers:                                  │   │
│  │  - Parse and normalize entity data                  │   │
│  │  - Extract relationships from references            │   │
│  │  - Build graph edges                                │   │
│  └──────────────────┬───────────────────────────────────┘   │
│                     │                                        │
│  ┌──────────────────▼───────────────────────────────────┐   │
│  │  ArangoDB Loader:                                    │   │
│  │  - Bulk insert documents                            │   │
│  │  - Create graph edges                               │   │
│  │  - Build search indexes                             │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### Deployment Architectures

**Docker Compose Stack**:
```yaml
services:
  arangodb:
    image: arangodb:latest
    volumes:
      - bron_data:/var/lib/arangodb3
    environment:
      - ARANGO_ROOT_PASSWORD
  
  bron-mcp:
    image: bron-mcp-gateway:latest
    depends_on:
      - arangodb
    volumes:
      - ./config.yaml:/app/config.yaml
      - ./data:/app/data  # For air-gapped data files
    environment:
      - DEPLOYMENT_MODE=cloud|on-prem|isolated
```

**Deployment Mode Behavior**:
- **Cloud/On-prem (internet)**: Build process downloads from NVD, MITRE, CAPEC APIs
- **Isolated networks**: Build process reads from `/app/data` directory (pre-populated data files)

### Data Flow

**Query Flow** (read operations):
1. MCP client sends tool call (e.g., `query_cve` with CVE-2023-1234)
2. MCP server validates input and routes to tool handler
3. Tool handler calls BRON query layer
4. Query layer executes AQL (ArangoDB Query Language) query
5. Results are formatted and returned via MCP protocol

**Update Flow** (internet-connected):
1. Admin invokes `update_knowledge_graph` tool or scheduled task triggers
2. Data fetchers download latest datasets from upstream sources
3. Transformers parse and normalize data
4. Loader performs transactional update to ArangoDB
5. Server logs version change and continues serving requests

**Export/Import Flow** (isolated network sync):
1. Internet-connected instance: `export_knowledge_graph` → creates JSON dump
2. Transfer dump file to isolated network environment (physical media, secure transfer)
3. Isolated network instance: `import_knowledge_graph` → loads dump into ArangoDB
4. Validation ensures data integrity, rollback on failure

## Components and Interfaces

### MCP Server Component

**Responsibilities**:
- Implement MCP protocol message handling
- Expose tools, resources, and prompts
- Manage server lifecycle (initialization, shutdown)
- Handle client connections (stdio transport)

**Key Interfaces**:

```python
class BronMCPServer:
    """Main MCP server implementation using official MCP SDK."""
    
    def __init__(self, config: ServerConfig, db_client: ArangoDBClient):
        """Initialize server with configuration and database client."""
        
    async def handle_initialize(self, request: InitializeRequest) -> InitializeResponse:
        """Handle MCP initialize request, return server capabilities."""
        
    async def handle_tools_list(self) -> ListToolsResponse:
        """Return list of available tools."""
        
    async def handle_tool_call(self, name: str, arguments: dict) -> ToolResponse:
        """Route tool calls to appropriate handlers."""
        
    async def handle_resources_list(self) -> ListResourcesResponse:
        """Return list of available resource URI templates."""
        
    async def handle_resource_read(self, uri: str) -> ResourceResponse:
        """Resolve and return resource data for given URI."""
        
    async def handle_prompts_list(self) -> ListPromptsResponse:
        """Return list of available prompts."""
        
    async def handle_prompt_get(self, name: str, arguments: dict) -> PromptResponse:
        """Generate prompt content based on template and arguments."""
```

**Tool Definitions** (MCP schema):

```python
TOOLS = [
    {
        "name": "query_cve",
        "description": "Query CVE vulnerability information by identifier",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "pattern": "^CVE-\\d{4}-\\d{4,}$"}
            },
            "required": ["cve_id"]
        }
    },
    {
        "name": "query_cwe",
        "description": "Query CWE weakness information by identifier",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cwe_id": {"type": "string", "pattern": "^CWE-\\d+$"}
            },
            "required": ["cwe_id"]
        }
    },
    {
        "name": "find_relationships",
        "description": "Find related entities in the BRON knowledge graph",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity_id": {"type": "string"},
                "relationship_type": {
                    "type": "string",
                    "enum": ["cve_to_cwe", "cwe_to_capec", "capec_to_attack", 
                             "attack_to_cve", "all"]
                },
                "max_depth": {"type": "integer", "minimum": 1, "maximum": 5, "default": 1}
            },
            "required": ["entity_id"]
        }
    },
    {
        "name": "search_bron",
        "description": "Full-text search across all BRON entities",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 3},
                "entity_types": {
                    "type": "array",
                    "items": {"enum": ["cve", "cwe", "attack", "capec"]},
                    "default": ["cve", "cwe", "attack", "capec"]
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}
            },
            "required": ["query"]
        }
    },
    # ... additional tools for data management
]
```

### BRON Query Layer Component

**Responsibilities**:
- Abstract ArangoDB query complexity
- Provide type-safe entity retrieval
- Execute graph traversal queries
- Implement full-text search

**Key Interfaces**:

```python
class BronQueryLayer:
    """High-level query interface for BRON knowledge graph."""
    
    def __init__(self, db_client: ArangoDBClient):
        """Initialize with ArangoDB client."""
        
    async def get_cve(self, cve_id: str) -> Optional[CVEEntity]:
        """Retrieve CVE entity by identifier."""
        
    async def get_cwe(self, cwe_id: str) -> Optional[CWEEntity]:
        """Retrieve CWE entity by identifier."""
        
    async def get_attack_technique(self, technique_id: str) -> Optional[AttackEntity]:
        """Retrieve ATT&CK technique by identifier."""
        
    async def get_capec(self, capec_id: str) -> Optional[CAPECEntity]:
        """Retrieve CAPEC pattern by identifier."""
        
    async def find_relationships(
        self, 
        entity_id: str, 
        relationship_type: str,
        max_depth: int = 1
    ) -> List[RelatedEntity]:
        """Traverse graph to find related entities."""
        
    async def search(
        self, 
        query: str, 
        entity_types: List[str],
        limit: int = 20
    ) -> List[SearchResult]:
        """Full-text search across entity descriptions and names."""
        
    async def get_data_version(self) -> DataVersion:
        """Retrieve knowledge graph version metadata."""
```

**Entity Models**:

```python
@dataclass
class CVEEntity:
    cve_id: str
    description: str
    published_date: datetime
    severity: str  # CVSS score or severity rating
    cvss_score: Optional[float]
    related_cwes: List[str]  # CWE identifiers
    related_attack_techniques: List[str]  # ATT&CK identifiers
    references: List[str]  # External URLs
    
@dataclass
class CWEEntity:
    cwe_id: str
    name: str
    description: str
    related_cves: List[str]
    related_capec: List[str]
    
@dataclass
class AttackEntity:
    technique_id: str
    name: str
    description: str
    tactics: List[str]  # ATT&CK tactics
    related_cves: List[str]
    
@dataclass
class CAPECEntity:
    capec_id: str
    name: str
    description: str
    prerequisites: List[str]
    related_cwes: List[str]
```

### ArangoDB Client Component

**Responsibilities**:
- Manage database connections and connection pooling
- Execute AQL queries
- Handle transactions for data updates
- Provide health check and connectivity validation

**Key Interfaces**:

```python
class ArangoDBClient:
    """Low-level ArangoDB client wrapper."""
    
    def __init__(self, config: DatabaseConfig):
        """Initialize with connection parameters."""
        
    async def connect(self) -> None:
        """Establish database connection, validate connectivity."""
        
    async def execute_query(self, aql: str, bind_vars: dict) -> List[dict]:
        """Execute AQL query with parameter binding."""
        
    async def get_document(self, collection: str, key: str) -> Optional[dict]:
        """Retrieve single document by key."""
        
    async def health_check(self) -> bool:
        """Verify database connectivity and responsiveness."""
        
    async def begin_transaction(self) -> Transaction:
        """Start a transaction for atomic updates."""
```

### Data Build Pipeline Component

**Responsibilities**:
- Download threat intelligence data from upstream sources
- Parse and normalize data formats (JSON, XML, STIX)
- Extract relationships from entity references
- Load data into ArangoDB collections
- Support both online and offline (air-gapped) modes

**Key Interfaces**:

```python
class DataBuildPipeline:
    """Orchestrates BRON knowledge graph construction."""
    
    def __init__(self, config: BuildConfig, db_client: ArangoDBClient):
        """Initialize with build configuration."""
        
    async def build(self, no_download: bool = False) -> BuildResult:
        """Execute full build pipeline."""
        
    async def fetch_data(self) -> FetchedData:
        """Download data from upstream sources (if not no_download)."""
        
    async def transform_data(self, fetched: FetchedData) -> TransformedData:
        """Parse and normalize data into graph structure."""
        
    async def load_data(self, transformed: TransformedData) -> None:
        """Load data into ArangoDB with transactional guarantees."""
        
    async def export_data(self, output_path: str) -> None:
        """Export knowledge graph to portable format."""
        
    async def import_data(self, input_path: str) -> None:
        """Import knowledge graph from portable format."""
```

**Data Fetchers**:

```python
class NVDFetcher:
    """Fetch CVE data from National Vulnerability Database API."""
    async def fetch(self) -> List[dict]:
        """Download CVE data, handle pagination and rate limiting."""

class MITREAttackFetcher:
    """Fetch ATT&CK data from MITRE STIX repository."""
    async def fetch(self) -> List[dict]:
        """Download ATT&CK techniques from STIX bundles."""

class CWEFetcher:
    """Fetch CWE data from MITRE CWE XML."""
    async def fetch(self) -> List[dict]:
        """Download and parse CWE XML data."""

class CAPECFetcher:
    """Fetch CAPEC data from MITRE CAPEC XML."""
    async def fetch(self) -> List[dict]:
        """Download and parse CAPEC XML data."""
```

### Configuration Component

**Configuration Schema**:

```yaml
server:
  name: "bron-mcp-gateway"
  version: "1.0.0"
  log_level: "INFO"  # DEBUG, INFO, WARNING, ERROR
  log_file: "/var/log/bron-mcp.log"

database:
  host: "arangodb"
  port: 8529
  username: "root"
  password: "${ARANGO_ROOT_PASSWORD}"
  database_name: "bron"
  connection_pool_size: 10

deployment:
  mode: "cloud"  # cloud, on-prem, isolated
  data_directory: "/app/data"  # For isolated network data files
  
updates:
  enabled: true  # Disable for isolated networks
  schedule: "0 2 * * *"  # Cron expression for automatic updates
  sources:
    nvd_api_key: "${NVD_API_KEY}"  # Optional, increases rate limit
```

**Configuration Loading**:

```python
@dataclass
class ServerConfig:
    name: str
    version: str
    log_level: str
    log_file: str

@dataclass
class DatabaseConfig:
    host: str
    port: int
    username: str
    password: str
    database_name: str
    connection_pool_size: int

@dataclass
class DeploymentConfig:
    mode: str  # cloud, on-prem, isolated
    data_directory: str

class ConfigLoader:
    """Load and validate configuration from YAML file."""
    
    @staticmethod
    def load(config_path: str) -> Config:
        """Load configuration, expand environment variables, validate schema."""
```

## Data Models

### ArangoDB Schema

**Collections** (document stores):

```javascript
// cves collection
{
  "_key": "CVE-2023-1234",  // CVE identifier as document key
  "cve_id": "CVE-2023-1234",
  "description": "Buffer overflow in...",
  "published_date": "2023-03-15T10:00:00Z",
  "severity": "HIGH",
  "cvss_score": 7.5,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "references": ["https://nvd.nist.gov/...", "https://..."],
  "last_modified": "2023-03-20T14:30:00Z"
}

// cwes collection
{
  "_key": "CWE-119",
  "cwe_id": "CWE-119",
  "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
  "description": "The software performs operations on a memory buffer...",
  "extended_description": "...",
  "related_weaknesses": ["CWE-120", "CWE-125"]
}

// attack_techniques collection
{
  "_key": "T1059",
  "technique_id": "T1059",
  "name": "Command and Scripting Interpreter",
  "description": "Adversaries may abuse command and script interpreters...",
  "tactics": ["execution"],
  "platforms": ["Linux", "macOS", "Windows"],
  "data_sources": ["Process: Process Creation", "Command: Command Execution"]
}

// capec_patterns collection
{
  "_key": "CAPEC-100",
  "capec_id": "CAPEC-100",
  "name": "Overflow Buffers",
  "description": "Buffer overflow attacks target...",
  "prerequisites": ["Target application reads input from user", "..."],
  "typical_severity": "High"
}
```

**Edge Collections** (relationships):

```javascript
// cve_to_cwe edges
{
  "_from": "cves/CVE-2023-1234",
  "_to": "cwes/CWE-119",
  "relationship_type": "exploits_weakness"
}

// cwe_to_capec edges
{
  "_from": "cwes/CWE-119",
  "_to": "capec_patterns/CAPEC-100",
  "relationship_type": "enables_attack_pattern"
}

// capec_to_attack edges
{
  "_from": "capec_patterns/CAPEC-100",
  "_to": "attack_techniques/T1059",
  "relationship_type": "implements_technique"
}

// attack_to_cve edges (reverse relationship)
{
  "_from": "attack_techniques/T1059",
  "_to": "cves/CVE-2023-1234",
  "relationship_type": "exploited_by_vulnerability"
}
```

**Graph Definition**:

```javascript
// BRON graph definition in ArangoDB
{
  "name": "bron_graph",
  "edgeDefinitions": [
    {
      "collection": "cve_to_cwe",
      "from": ["cves"],
      "to": ["cwes"]
    },
    {
      "collection": "cwe_to_capec",
      "from": ["cwes"],
      "to": ["capec_patterns"]
    },
    {
      "collection": "capec_to_attack",
      "from": ["capec_patterns"],
      "to": ["attack_techniques"]
    },
    {
      "collection": "attack_to_cve",
      "from": ["attack_techniques"],
      "to": ["cves"]
    }
  ]
}
```

**Indexes**:

```javascript
// Full-text search indexes
db.cves.ensureIndex({ type: "fulltext", fields: ["description"], minLength: 3 });
db.cwes.ensureIndex({ type: "fulltext", fields: ["name", "description"], minLength: 3 });
db.attack_techniques.ensureIndex({ type: "fulltext", fields: ["name", "description"], minLength: 3 });
db.capec_patterns.ensureIndex({ type: "fulltext", fields: ["name", "description"], minLength: 3 });

// Hash indexes for fast lookups
db.cves.ensureIndex({ type: "hash", fields: ["cve_id"], unique: true });
db.cwes.ensureIndex({ type: "hash", fields: ["cwe_id"], unique: true });
db.attack_techniques.ensureIndex({ type: "hash", fields: ["technique_id"], unique: true });
db.capec_patterns.ensureIndex({ type: "hash", fields: ["capec_id"], unique: true });
```

### MCP Protocol Messages

**Tool Call Example**:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "query_cve",
    "arguments": {
      "cve_id": "CVE-2023-1234"
    }
  }
}
```

**Tool Response Example**:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "CVE-2023-1234: Buffer overflow vulnerability...\n\nSeverity: HIGH (CVSS 7.5)\nPublished: 2023-03-15\n\nRelated Weaknesses:\n- CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer\n\nRelated ATT&CK Techniques:\n- T1059: Command and Scripting Interpreter\n\nReferences:\n- https://nvd.nist.gov/vuln/detail/CVE-2023-1234"
      }
    ]
  }
}
```

**Resource URI Examples**:

```
bron://cve/CVE-2023-1234
bron://cwe/CWE-119
bron://attack/T1059
bron://capec/CAPEC-100
```

**Resource Response Example**:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "contents": [
      {
        "uri": "bron://cve/CVE-2023-1234",
        "mimeType": "application/json",
        "text": "{\"cve_id\": \"CVE-2023-1234\", \"description\": \"...\", ...}"
      }
    ]
  }
}
```

### Export/Import Format

**Export File Structure** (JSON):

```json
{
  "version": "1.0",
  "export_timestamp": "2024-01-15T10:30:00Z",
  "data_version": {
    "nvd_last_modified": "2024-01-14T23:59:59Z",
    "attack_version": "14.1",
    "cwe_version": "4.13",
    "capec_version": "3.9"
  },
  "collections": {
    "cves": [
      {"_key": "CVE-2023-1234", "cve_id": "CVE-2023-1234", ...},
      ...
    ],
    "cwes": [...],
    "attack_techniques": [...],
    "capec_patterns": [...]
  },
  "edges": {
    "cve_to_cwe": [
      {"_from": "cves/CVE-2023-1234", "_to": "cwes/CWE-119", ...},
      ...
    ],
    "cwe_to_capec": [...],
    "capec_to_attack": [...],
    "attack_to_cve": [...]
  },
  "metadata": {
    "total_cves": 250000,
    "total_cwes": 900,
    "total_attack_techniques": 600,
    "total_capec_patterns": 550,
    "total_relationships": 500000
  }
}
```


## Agentic Workflow Prompts

### Overview

The BRON MCP Gateway provides specialized prompts designed for AI coding agents (Cline, Roo, LangChain, Kiro, etc.) to make security-informed decisions during code development and execution. These prompts guide agents through structured queries of the BRON knowledge graph to assess security risks before taking actions like executing generated code, installing dependencies, or committing changes.

This is a critical capability for making AI-generated code safer: by checking generated code patterns against BRON's knowledge of CVEs, CWEs, CAPEC attack patterns, and ATT&CK techniques, agents can prevent execution of code with known vulnerability patterns.

### Design Philosophy

**Prevent, Don't Just Detect**: Agentic workflow prompts are designed to help agents make safer decisions proactively, not just report issues after the fact. Each prompt provides a decision framework that helps agents determine whether an action is safe to proceed.

**Code Execution Safety**: A primary use case is preventing execution of dynamically generated code that matches known vulnerability patterns. Before executing any generated code, agents can validate it against BRON to identify CWE patterns, related CVEs, and CAPEC attack vectors.

**Structured Guidance**: Rather than returning raw data, prompts provide step-by-step guidance for querying BRON and interpreting results in the context of the agent's current task.

**Integration Points**: Prompts are designed to integrate with agent decision loops at key points:
- Before executing dynamically generated code (code execution safety validation)
- Before installing or updating dependencies (dependency vulnerability assessment)
- During code generation (to avoid vulnerable patterns)
- During code review (to identify security issues)
- Before committing changes (pre-commit security checks)
- During architecture design (threat modeling)
- When refactoring code (security regression detection)

### Prompt Definitions

#### 1. validate_code_execution_safety

**Purpose**: Help agents decide whether dynamically generated code is safe to execute.

**Use Case**: An agent generates code to solve a user's problem. Before executing it, the agent invokes this prompt to check if the code contains patterns matching known vulnerabilities.

**Input Schema**:
```json
{
  "code_snippet": "string (the generated code)",
  "language": "string (python, javascript, java, etc.)",
  "execution_context": "string (optional: where/how code will run)"
}
```

**Prompt Template**:
```
You are about to execute the following {language} code:

```{language}
{code_snippet}
```

To assess execution safety, follow these steps:

1. PATTERN ANALYSIS: Identify code patterns that may match known CWE weaknesses:
   - Use search_bron to find CWEs related to: {identified_patterns}
   - Focus on CWEs in categories: Input Validation, Memory Safety, Injection, Path Traversal

2. RISK ASSESSMENT: For each identified CWE:
   - Use query_cwe to get detailed weakness information
   - Use find_relationships to discover related CVEs and CAPEC patterns
   - Assess severity: Are there recent CVEs exploiting this weakness?

3. EXECUTION DECISION:
   - HIGH RISK: Code matches CWE patterns with active CVE exploitation → DO NOT EXECUTE
   - MEDIUM RISK: Code matches CWE patterns but no recent CVEs → WARN USER, request approval
   - LOW RISK: No CWE pattern matches or only theoretical weaknesses → SAFE TO EXECUTE

4. MITIGATION: If risks identified, suggest secure alternatives:
   - Query related CWEs for secure coding patterns
   - Recommend input validation, sanitization, or safer APIs

Example high-risk patterns to check:
- SQL query construction from user input (CWE-89: SQL Injection)
- File path operations with user input (CWE-22: Path Traversal)
- Command execution with user input (CWE-78: OS Command Injection)
- Deserialization of untrusted data (CWE-502: Deserialization of Untrusted Data)
- Memory operations without bounds checking (CWE-119: Buffer Overflow)

DECISION: [EXECUTE / WARN / BLOCK]
REASONING: [Your analysis based on BRON queries]
```

**Integration Example (Cline/Roo)**:
```python
# Before executing generated code
prompt_result = await mcp_client.get_prompt(
    "validate_code_execution_safety",
    {"code_snippet": generated_code, "language": "python"}
)

# Agent uses prompt guidance to query BRON
decision = await agent.analyze_with_bron(prompt_result)

if decision == "BLOCK":
    return "Code execution blocked due to security risks"
elif decision == "WARN":
    user_approval = await ask_user("Code has potential risks. Execute anyway?")
    if not user_approval:
        return "Execution cancelled by user"
```

#### 2. assess_dependency_vulnerabilities

**Purpose**: Help agents evaluate dependencies for known vulnerabilities before installation.

**Use Case**: User asks agent to install a package. Agent checks for CVEs before running `npm install` or `pip install`.

**Input Schema**:
```json
{
  "package_name": "string",
  "version": "string (optional, or 'latest')",
  "ecosystem": "string (npm, pypi, maven, etc.)"
}
```

**Prompt Template**:
```
You are considering installing: {package_name}@{version} from {ecosystem}

To assess dependency safety, follow these steps:

1. CVE SEARCH: Search for known vulnerabilities:
   - Use search_bron with query: "{package_name}"
   - Filter results to CVE entity types
   - Look for CVEs mentioning the package name in descriptions

2. VERSION ANALYSIS: For each CVE found:
   - Use query_cve to get detailed vulnerability information
   - Check if the CVE affects version {version}
   - Note CVSS score and severity rating
   - Check published date (recent CVEs are higher priority)

3. WEAKNESS ANALYSIS: Understand vulnerability types:
   - Use find_relationships to get related CWEs
   - Use query_cwe to understand weakness categories
   - Identify if vulnerabilities are remotely exploitable

4. TRANSITIVE RISK: Consider dependency chain:
   - Note if package has many dependencies (larger attack surface)
   - Recommend checking transitive dependencies separately

5. DECISION FRAMEWORK:
   - CRITICAL CVEs (CVSS >= 9.0) in target version → BLOCK installation
   - HIGH CVEs (CVSS >= 7.0) in target version → WARN, suggest patched version
   - MEDIUM/LOW CVEs or CVEs in older versions → INFORM user, safe to proceed
   - No CVEs found → SAFE to install

6. RECOMMENDATIONS:
   - If CVEs found, identify safe version ranges
   - Suggest alternative packages if no safe version available
   - Recommend security monitoring for the dependency

DECISION: [INSTALL / WARN / BLOCK / SUGGEST_ALTERNATIVE]
SAFE_VERSIONS: [List of versions without known CVEs]
REASONING: [Your analysis based on BRON queries]
```

#### 3. guide_secure_code_generation

**Purpose**: Provide security guidance during code generation to avoid introducing vulnerabilities.

**Use Case**: User requests code to implement a feature. Agent consults this prompt to understand security considerations before generating code.

**Input Schema**:
```json
{
  "feature_description": "string (what the code should do)",
  "language": "string",
  "context": "string (optional: existing codebase context)"
}
```

**Prompt Template**:
```
You are generating code for: {feature_description}

To generate secure code, follow these steps:

1. IDENTIFY SECURITY-RELEVANT OPERATIONS:
   - Does the feature involve: user input, file operations, network requests, authentication, data storage, cryptography?
   - List security-relevant operations: {operations}

2. QUERY RELEVANT CWES:
   For each operation type, search for related weaknesses:
   - User input → search_bron("input validation injection")
   - File operations → search_bron("path traversal file inclusion")
   - Network requests → search_bron("SSRF request forgery")
   - Authentication → search_bron("authentication bypass")
   - Data storage → search_bron("SQL injection XSS")
   - Cryptography → search_bron("weak cryptography")

3. UNDERSTAND VULNERABILITY PATTERNS:
   For top CWEs found:
   - Use query_cwe to understand the weakness
   - Use find_relationships to see real-world CVE examples
   - Note common mistake patterns that lead to the weakness

4. APPLY SECURE CODING PATTERNS:
   - Input validation: Whitelist validation, type checking, length limits
   - Output encoding: Context-appropriate escaping (HTML, SQL, shell)
   - Authentication: Use established libraries, never roll your own crypto
   - File operations: Validate paths, use safe APIs, restrict permissions
   - Error handling: Don't leak sensitive information in error messages

5. GENERATE CODE WITH SECURITY CONTROLS:
   - Include input validation before processing
   - Use parameterized queries for databases
   - Use safe APIs (e.g., subprocess with shell=False)
   - Add comments explaining security considerations

6. DOCUMENT SECURITY ASSUMPTIONS:
   - Note what inputs are trusted vs untrusted
   - Document required security configurations
   - List security testing recommendations

SECURE_PATTERNS: [List of CWE-informed secure coding patterns to apply]
AVOID_PATTERNS: [List of CWE patterns to avoid]
GENERATED_CODE: [Your secure implementation]
```

#### 4. analyze_attack_surface

**Purpose**: Help agents understand security implications of code changes.

**Use Case**: Agent is about to make changes that add new functionality. This prompt helps assess how the changes affect the attack surface.

**Input Schema**:
```json
{
  "change_description": "string (what's being added/modified)",
  "code_diff": "string (optional: actual diff)",
  "exposed_interfaces": "array (APIs, endpoints, file operations, etc.)"
}
```

**Prompt Template**:
```
You are analyzing attack surface changes for: {change_description}

Exposed interfaces: {exposed_interfaces}

Follow these steps to assess security impact:

1. MAP TO ATT&CK TECHNIQUES:
   For each exposed interface, identify potential attack techniques:
   - API endpoints → search_bron("API exploitation injection")
   - File uploads → search_bron("malicious file upload")
   - User authentication → search_bron("credential access")
   - Data processing → search_bron("code injection deserialization")

2. IDENTIFY ATTACK VECTORS:
   For each ATT&CK technique found:
   - Use query_attack_technique to understand attacker methods
   - Use find_relationships to discover related CAPEC patterns
   - Use query_capec to understand attack prerequisites

3. ASSESS EXPLOITABILITY:
   - Are exposed interfaces accessible remotely or only locally?
   - Is authentication required?
   - What privileges are needed?
   - Rate: [CRITICAL / HIGH / MEDIUM / LOW] exploitability

4. DISCOVER RELATED VULNERABILITIES:
   - Use find_relationships from CAPEC to CWE to CVE
   - Identify real-world examples of similar attack surfaces being exploited
   - Note CVSS scores and exploitation frequency

5. RECOMMEND MITIGATIONS:
   - Input validation and sanitization requirements
   - Authentication and authorization controls
   - Rate limiting and abuse prevention
   - Logging and monitoring recommendations
   - Security testing requirements (fuzzing, penetration testing)

6. QUANTIFY RISK:
   - Attack surface expansion: [SIGNIFICANT / MODERATE / MINIMAL]
   - Recommended security controls: [List]
   - Required security testing: [List]

ATTACK_SURFACE_DELTA: [Quantified change in attack surface]
MITIGATIONS: [Specific security controls to implement]
TESTING_RECOMMENDATIONS: [Security tests to perform]
```

#### 5. recognize_vulnerability_patterns

**Purpose**: Help agents identify potential security issues during code review.

**Use Case**: Agent is reviewing code (user's or its own) and needs to flag potential vulnerabilities.

**Input Schema**:
```json
{
  "code_snippet": "string",
  "language": "string",
  "review_context": "string (optional: what to focus on)"
}
```

**Prompt Template**:
```
You are reviewing the following {language} code for security issues:

```{language}
{code_snippet}
```

Follow these steps to identify vulnerability patterns:

1. PATTERN RECOGNITION:
   Scan code for common vulnerability indicators:
   - String concatenation in SQL/shell commands
   - User input flowing to sensitive sinks (eval, exec, system)
   - Missing input validation or sanitization
   - Hardcoded credentials or secrets
   - Unsafe deserialization
   - Missing authentication/authorization checks
   - Weak cryptographic algorithms
   - Race conditions in file operations

2. MAP PATTERNS TO CWES:
   For each identified pattern:
   - Use search_bron to find matching CWE definitions
   - Use query_cwe to get detailed weakness information
   - Confirm the pattern matches the CWE description

3. ASSESS SEVERITY:
   For each confirmed CWE:
   - Use find_relationships to find related CVEs
   - Check CVSS scores of related CVEs
   - Determine if the weakness is actively exploited
   - Rate severity: [CRITICAL / HIGH / MEDIUM / LOW / INFO]

4. DISTINGUISH FALSE POSITIVES:
   - Check if mitigations are already in place
   - Consider if the code path is actually reachable
   - Assess if inputs are already validated elsewhere
   - Confidence level: [HIGH / MEDIUM / LOW]

5. PROVIDE SPECIFIC FEEDBACK:
   For each issue found:
   - Line number and code excerpt
   - CWE reference and description
   - Explanation of why it's vulnerable
   - Specific remediation advice
   - Example of secure alternative

FINDINGS: [List of identified issues with CWE references]
RECOMMENDATIONS: [Specific fixes for each issue]
```

#### 6. discover_exploit_chains

**Purpose**: Help agents understand how multiple vulnerabilities could be chained together.

**Use Case**: Agent has identified multiple potential issues and wants to understand if they could be combined for greater impact.

**Input Schema**:
```json
{
  "vulnerability_ids": "array (CVE or CWE identifiers)",
  "system_context": "string (optional: system architecture)"
}
```

**Prompt Template**:
```
You are analyzing potential exploit chains involving: {vulnerability_ids}

Follow these steps to discover exploitation sequences:

1. BUILD VULNERABILITY GRAPH:
   For each vulnerability:
   - Use query_cve or query_cwe to get details
   - Use find_relationships to discover connections
   - Map relationships: CVE → CWE → CAPEC → ATT&CK

2. IDENTIFY ATTACK PATTERNS:
   - Use query_capec for each related CAPEC pattern
   - Look for patterns that chain multiple weaknesses
   - Note attack prerequisites and required conditions

3. DISCOVER MULTI-STAGE ATTACKS:
   - Can one vulnerability provide access needed for another?
   - Example: Info disclosure (CWE-200) → enables authentication bypass (CWE-287)
   - Example: XSS (CWE-79) → enables CSRF (CWE-352)
   - Use find_relationships to traverse attack chains

4. MAP TO ATT&CK TACTICS:
   - Initial Access → Execution → Persistence → Privilege Escalation
   - Use query_attack_technique to understand each stage
   - Identify which vulnerabilities enable which tactics

5. ASSESS COMBINED IMPACT:
   - Individual vulnerability severity: [List]
   - Combined exploit chain severity: [CRITICAL / HIGH / MEDIUM / LOW]
   - Likelihood of successful exploitation: [HIGH / MEDIUM / LOW]

6. PRIORITIZE REMEDIATION:
   - Which vulnerability breaks the most exploit chains if fixed?
   - Recommend fixing order based on maximum impact
   - Suggest defense-in-depth controls

EXPLOIT_CHAINS: [Documented attack sequences]
CRITICAL_VULNERABILITIES: [Vulnerabilities that enable multiple chains]
REMEDIATION_PRIORITY: [Ordered list of fixes]
```

#### 7. recommend_security_controls

**Purpose**: Help agents suggest appropriate mitigations for identified risks.

**Use Case**: Agent has identified a security issue and needs to recommend specific fixes.

**Input Schema**:
```json
{
  "weakness_ids": "array (CWE or CAPEC identifiers)",
  "context": "string (code context, architecture)"
}
```

**Prompt Template**:
```
You are recommending security controls for: {weakness_ids}

Follow these steps to identify effective mitigations:

1. UNDERSTAND THE WEAKNESS:
   For each CWE:
   - Use query_cwe to get detailed information
   - Note the weakness description and consequences
   - Identify the root cause of the weakness

2. IDENTIFY DEFENSIVE TECHNIQUES:
   - Use find_relationships to discover related ATT&CK techniques
   - Use query_attack_technique to understand attack methods
   - Identify which defensive controls counter these techniques

3. MAP TO MITIGATION STRATEGIES:
   Common mitigation categories:
   - Input validation and sanitization
   - Output encoding and escaping
   - Authentication and authorization
   - Cryptographic controls
   - Secure configuration
   - Error handling and logging
   - Rate limiting and resource controls

4. PROVIDE CODE-LEVEL MITIGATIONS:
   - Specific API calls or libraries to use
   - Code patterns that prevent the weakness
   - Example implementations in the target language

5. PROVIDE ARCHITECTURAL MITIGATIONS:
   - Network segmentation
   - Principle of least privilege
   - Defense in depth layers
   - Security monitoring and alerting

6. PRIORITIZE CONTROLS:
   - Effectiveness: How well does it mitigate the risk?
   - Implementation cost: How difficult to implement?
   - Performance impact: Does it affect system performance?
   - Recommended priority: [HIGH / MEDIUM / LOW]

RECOMMENDED_CONTROLS: [Ordered list of mitigations]
CODE_EXAMPLES: [Specific secure coding patterns]
ARCHITECTURAL_RECOMMENDATIONS: [System-level controls]
```

#### 8. assist_threat_modeling

**Purpose**: Help agents identify security requirements early in development.

**Use Case**: User describes a new feature or system. Agent uses this prompt to identify potential threats before implementation.

**Input Schema**:
```json
{
  "system_description": "string (architecture, components, data flows)",
  "assets": "array (what needs protection)",
  "trust_boundaries": "array (where untrusted data enters)"
}
```

**Prompt Template**:
```
You are performing threat modeling for: {system_description}

Assets to protect: {assets}
Trust boundaries: {trust_boundaries}

Follow these steps to identify threats:

1. IDENTIFY ATTACK VECTORS:
   For each trust boundary:
   - What untrusted data enters the system?
   - Use search_bron to find relevant attack patterns
   - Focus on: injection, authentication, authorization, data exposure

2. MAP TO ATT&CK TACTICS:
   For each system component:
   - Use search_bron with component type (API, database, file system, etc.)
   - Identify relevant ATT&CK techniques
   - Use query_attack_technique for detailed attack methods

3. DISCOVER APPLICABLE ATTACK PATTERNS:
   - Use find_relationships from ATT&CK to CAPEC
   - Use query_capec to understand attack prerequisites
   - Assess which patterns apply to your system architecture

4. IDENTIFY RELEVANT WEAKNESSES:
   - Use find_relationships from CAPEC to CWE
   - Use query_cwe to understand weakness categories
   - Prioritize CWEs relevant to your technology stack

5. GENERATE THREAT SCENARIOS:
   For each identified threat:
   - Threat: [Description]
   - Attack vector: [How attacker gains access]
   - Exploited weakness: [CWE reference]
   - Impact: [What attacker achieves]
   - Likelihood: [HIGH / MEDIUM / LOW]
   - Risk: [CRITICAL / HIGH / MEDIUM / LOW]

6. DEFINE SECURITY REQUIREMENTS:
   For each threat:
   - Required security control
   - Acceptance criteria for the control
   - Testing requirements

THREAT_SCENARIOS: [List of identified threats with ATT&CK/CAPEC/CWE references]
SECURITY_REQUIREMENTS: [Derived security requirements]
TESTING_REQUIREMENTS: [Security tests to implement]
```

#### 9. detect_security_regressions

**Purpose**: Help agents prevent reintroduction of previously fixed vulnerabilities.

**Use Case**: Agent is reviewing code changes and needs to check if they reintroduce old security issues.

**Input Schema**:
```json
{
  "code_changes": "string (diff or description)",
  "historical_fixes": "array (optional: previous CVE/CWE fixes)",
  "commit_history": "string (optional: relevant commit messages)"
}
```

**Prompt Template**:
```
You are checking for security regressions in: {code_changes}

Historical security fixes: {historical_fixes}

Follow these steps to detect regressions:

1. IDENTIFY PREVIOUSLY FIXED WEAKNESSES:
   For each historical fix:
   - Use query_cve or query_cwe to understand the original vulnerability
   - Note the vulnerable code pattern that was fixed
   - Identify the secure pattern that replaced it

2. ANALYZE CURRENT CHANGES:
   - Does the new code reintroduce the vulnerable pattern?
   - Are security controls being removed or weakened?
   - Is validated input becoming unvalidated?
   - Are safe APIs being replaced with unsafe ones?

3. PATTERN MATCHING:
   - Use search_bron to find CWEs matching current code patterns
   - Compare against CWEs from historical fixes
   - Flag matches as potential regressions

4. ASSESS REGRESSION RISK:
   For each potential regression:
   - Confidence: [HIGH / MEDIUM / LOW] that it's a true regression
   - Severity: [CRITICAL / HIGH / MEDIUM / LOW] if it is a regression
   - Affected functionality: [Description]

5. PROVIDE EVIDENCE:
   - Original vulnerable code pattern
   - Fixed code pattern
   - Current code pattern
   - Explanation of why it's a regression

6. RECOMMEND ACTIONS:
   - Block commit if high-confidence critical regression
   - Require security review if medium confidence
   - Add regression test to prevent future reintroduction

REGRESSIONS_DETECTED: [List of potential regressions]
EVIDENCE: [Code comparisons and CWE references]
RECOMMENDED_ACTION: [BLOCK / REVIEW / WARN / PASS]
```

#### 10. map_compliance_standards

**Purpose**: Help agents map vulnerabilities to compliance requirements.

**Use Case**: Organization has compliance requirements (PCI-DSS, HIPAA, SOC2). Agent needs to explain how security issues relate to compliance.

**Input Schema**:
```json
{
  "vulnerability_ids": "array (CVE or CWE identifiers)",
  "compliance_frameworks": "array (optional: specific frameworks to check)"
}
```

**Prompt Template**:
```
You are mapping vulnerabilities to compliance standards: {vulnerability_ids}

Target frameworks: {compliance_frameworks or "all common frameworks"}

Follow these steps to map compliance requirements:

1. UNDERSTAND THE VULNERABILITIES:
   For each vulnerability:
   - Use query_cve or query_cwe to get details
   - Note the weakness category and impact
   - Identify affected security properties (confidentiality, integrity, availability)

2. MAP TO COMMON STANDARDS:
   Check against major frameworks:
   - OWASP Top 10: Use search_bron to find if CWE is in current Top 10
   - CWE Top 25: Check if CWE is in Most Dangerous Software Weaknesses
   - SANS Top 25: Check for inclusion in SANS list
   - PCI-DSS: Requirements 6.5.x (secure coding), 6.6 (vulnerability management)
   - HIPAA: Security Rule requirements for data protection
   - SOC 2: Trust Services Criteria (Security, Availability, Confidentiality)

3. IDENTIFY SPECIFIC REQUIREMENTS:
   For each framework:
   - Which specific requirement does the vulnerability violate?
   - What evidence is needed to demonstrate compliance?
   - What remediation is required for compliance?

4. ASSESS COMPLIANCE IMPACT:
   - Does this vulnerability cause non-compliance?
   - Severity of compliance violation: [CRITICAL / HIGH / MEDIUM / LOW]
   - Potential penalties or audit findings

5. PRIORITIZE REMEDIATION:
   - Compliance-driven priority: [URGENT / HIGH / MEDIUM / LOW]
   - Deadline considerations (audit dates, certification renewals)
   - Dependencies (what else must be fixed together)

6. GENERATE COMPLIANCE REPORT:
   - Vulnerability summary with CWE/CVE references
   - Affected compliance requirements
   - Required remediation actions
   - Evidence needed to demonstrate fix
   - Recommended timeline

COMPLIANCE_MAPPINGS: [Vulnerability → Framework → Requirement]
VIOLATIONS: [List of compliance violations]
REMEDIATION_PLAN: [Prioritized actions with compliance context]
AUDIT_EVIDENCE: [What to document for auditors]
```

#### 11. pre_commit_security_check

**Purpose**: Comprehensive security check before committing code changes.

**Use Case**: Agent is about to commit code. This prompt provides a final security gate.

**Input Schema**:
```json
{
  "staged_changes": "string (git diff or file list)",
  "commit_message": "string",
  "changed_files": "array (file paths)"
}
```

**Prompt Template**:
```
You are performing pre-commit security checks for: {commit_message}

Changed files: {changed_files}

Follow these steps for comprehensive security review:

1. VULNERABILITY PATTERN SCAN:
   - Use recognize_vulnerability_patterns prompt for each changed file
   - Identify any CWE patterns in the code
   - Flag high-severity issues

2. DEPENDENCY CHECK:
   - If package files changed (package.json, requirements.txt, pom.xml):
   - Use assess_dependency_vulnerabilities for new/updated dependencies
   - Block commit if critical CVEs found

3. ATTACK SURFACE ANALYSIS:
   - If new APIs, endpoints, or interfaces added:
   - Use analyze_attack_surface prompt
   - Assess if security controls are adequate

4. REGRESSION CHECK:
   - Use detect_security_regressions prompt
   - Check if changes reintroduce old vulnerabilities
   - Review commit history for related security fixes

5. SECRETS DETECTION:
   - Scan for hardcoded credentials, API keys, tokens
   - Flag any potential secrets in code or config files
   - Recommend using environment variables or secret management

6. SECURITY TEST COVERAGE:
   - Are security tests included for new functionality?
   - Are edge cases and error conditions tested?
   - Recommend additional security tests if needed

7. COMMIT DECISION:
   - BLOCK: Critical security issues found → must fix before commit
   - WARN: Medium issues found → recommend fix but allow commit with acknowledgment
   - PASS: No significant security issues → safe to commit

SECURITY_ISSUES: [List of all identified issues]
BLOCKING_ISSUES: [Critical issues that prevent commit]
WARNINGS: [Non-blocking issues to address]
COMMIT_DECISION: [BLOCK / WARN / PASS]
RECOMMENDED_ACTIONS: [What to do before/after commit]
```

### Integration Patterns for AI Agents

#### Cline Integration Example

```typescript
// Cline agent decision loop
async function executeGeneratedCode(code: string, language: string) {
  // Get security validation prompt
  const prompt = await mcpClient.getPrompt("validate_code_execution_safety", {
    code_snippet: code,
    language: language,
    execution_context: "user workspace"
  });
  
  // Follow prompt guidance to query BRON
  const patterns = identifyCodePatterns(code);
  const cwes = await Promise.all(
    patterns.map(p => mcpClient.callTool("search_bron", { query: p }))
  );
  
  // Assess risk based on CWE findings
  const highRiskCWEs = cwes.filter(cwe => hasRecentCVEs(cwe));
  
  if (highRiskCWEs.length > 0) {
    // Block execution
    return {
      action: "block",
      reason: `Code matches high-risk patterns: ${highRiskCWEs.map(c => c.cwe_id).join(", ")}`,
      details: highRiskCWEs
    };
  }
  
  // Safe to execute
  return { action: "execute" };
}
```

#### Roo Integration Example

```python
# Roo agent dependency installation hook
async def before_install_package(package: str, version: str):
    # Get dependency assessment prompt
    prompt = await mcp_client.get_prompt("assess_dependency_vulnerabilities", {
        "package_name": package,
        "version": version,
        "ecosystem": "pypi"
    })
    
    # Search for CVEs
    cves = await mcp_client.call_tool("search_bron", {
        "query": package,
        "entity_types": ["cve"]
    })
    
    # Check severity
    critical_cves = [
        cve for cve in cves 
        if cve.get("cvss_score", 0) >= 9.0 and affects_version(cve, version)
    ]
    
    if critical_cves:
        # Block installation
        safe_versions = find_safe_versions(package, cves)
        raise SecurityError(
            f"Critical CVEs found in {package}@{version}. "
            f"Safe versions: {safe_versions}"
        )
    
    # Safe to install
    return True
```

#### LangChain Integration Example

```python
# LangChain agent with BRON security tool
from langchain.agents import Tool
from langchain.agents import initialize_agent

async def bron_security_check(code: str) -> str:
    """Security check using BRON MCP gateway."""
    prompt = await mcp_client.get_prompt("recognize_vulnerability_patterns", {
        "code_snippet": code,
        "language": "python"
    })
    
    # Agent follows prompt to query BRON
    findings = await analyze_code_with_bron(code, prompt)
    
    if findings["critical_issues"]:
        return f"SECURITY RISK: {findings['critical_issues']}"
    return "Code appears safe"

# Add as tool to LangChain agent
security_tool = Tool(
    name="SecurityCheck",
    func=bron_security_check,
    description="Check code for security vulnerabilities using BRON knowledge graph"
)

agent = initialize_agent(
    tools=[security_tool, ...],
    llm=llm,
    agent="zero-shot-react-description"
)
```

### Prompt Response Format

All agentic workflow prompts return structured guidance in this format:

```json
{
  "prompt": {
    "name": "validate_code_execution_safety",
    "description": "Assess whether generated code is safe to execute",
    "arguments": {
      "code_snippet": "...",
      "language": "python"
    }
  },
  "messages": [
    {
      "role": "user",
      "content": {
        "type": "text",
        "text": "[Full prompt template with guidance steps]"
      }
    }
  ],
  "suggested_tools": [
    "search_bron",
    "query_cwe",
    "find_relationships"
  ],
  "decision_framework": {
    "risk_levels": ["HIGH", "MEDIUM", "LOW"],
    "actions": ["EXECUTE", "WARN", "BLOCK"],
    "criteria": "..."
  }
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Entity Retrieval Completeness

*For any* valid entity identifier (CVE, CWE, ATT&CK technique, or CAPEC pattern) that exists in the knowledge graph, querying that entity through the appropriate tool (query_cve, query_cwe, query_attack_technique, query_capec) should return the entity's complete data including all required fields (description, relationships, and entity-specific metadata).

**Validates: Requirements 2.2, 2.4, 3.2, 3.4, 4.2, 4.4, 5.2, 5.4**

### Property 2: Invalid Entity Error Handling

*For any* entity identifier that does not exist in the knowledge graph, querying that entity through any query tool should return a structured error response indicating the entity was not found, and the error should include the entity type and identifier that was queried.

**Validates: Requirements 2.3, 3.3, 4.3, 5.3, 8.3**

### Property 3: Relationship Traversal Correctness

*For any* entity identifier and relationship type, the find_relationships tool should return exactly the set of entities that are connected via edges of that relationship type in the knowledge graph, with no duplicates and no missing connections.

**Validates: Requirements 6.2**

### Property 4: Empty Relationship Handling

*For any* entity that has no outgoing edges of a specified relationship type, the find_relationships tool should return an empty result set (not an error), allowing clients to distinguish between "entity not found" and "entity has no relationships".

**Validates: Requirements 6.4**

### Property 5: Search Result Relevance

*For any* search query string, all returned results from search_bron should contain the search terms in at least one of the searchable fields (CVE description, CWE name/description, ATT&CK technique name/description, or CAPEC pattern name/description), and each result should include entity type, identifier, and relevance score.

**Validates: Requirements 7.2, 7.3, 7.4**

### Property 6: Resource URI Resolution

*For any* valid entity in the knowledge graph, constructing a resource URI in the format bron://{entity_type}/{entity_id} and requesting it through the resources/read endpoint should return the same entity data as querying through the corresponding tool.

**Validates: Requirements 8.2**

### Property 7: MCP Protocol Response Structure

*For any* valid MCP request (tools/call, resources/read, prompts/get), the response should conform to the MCP protocol specification with proper JSON-RPC 2.0 structure, including jsonrpc version, id matching the request, and either a result or error field.

**Validates: Requirements 13.4**

### Property 8: Comprehensive Operation Logging

*For any* tool invocation, resource access, or error condition, the server should create a log entry containing timestamp, operation type, parameters (sanitized for sensitive data), and outcome (success/failure), enabling complete audit trails.

**Validates: Requirements 11.2, 11.3, 14.3**

### Property 9: Error Response Structure

*For any* error condition (invalid input, database unavailability, missing entity), the server should return a structured error response containing an error code, human-readable message, and contextual information about what was attempted, without exposing sensitive system details.

**Validates: Requirements 11.1**

### Property 10: Configuration Application

*For any* valid configuration parameter (database connection, logging level, data source location), changing that parameter in the configuration file and restarting the server should result in the server operating according to the new configuration value.

**Validates: Requirements 12.2, 12.3, 22.1**

### Property 11: Concurrent Request Handling

*For any* set of concurrent client requests (including during knowledge graph reload operations), the server should process all requests without data corruption, race conditions, or request rejection, maintaining response correctness for each individual request.

**Validates: Requirements 15.1, 14.4**

### Property 12: Request Queueing Under Load

*For any* overload condition where request rate exceeds processing capacity, the server should queue incoming requests rather than rejecting them, and should process queued requests in order once capacity becomes available.

**Validates: Requirements 15.4**

### Property 13: Knowledge Graph Reload Continuity

*For any* knowledge graph reload operation (triggered by update_knowledge_graph or import_knowledge_graph), the server should continue serving requests using the existing data until the new data is fully loaded and validated, then atomically switch to the new data without downtime.

**Validates: Requirements 14.2**

### Property 14: Export-Import Round Trip

*For any* knowledge graph state, exporting the data using export_knowledge_graph and then importing it using import_knowledge_graph should result in an identical knowledge graph state, preserving all entities, relationships, and metadata including version information and timestamps.

**Validates: Requirements 18.4, 20.2, 20.3, 20.5**

### Property 15: Invalid Import Safety

*For any* invalid or corrupted export file provided to import_knowledge_graph, the import should fail with a descriptive error, and the existing knowledge graph data should remain unchanged and operational.

**Validates: Requirements 20.6**

### Property 16: Update Failure Resilience

*For any* failure during the update_knowledge_graph operation (network error, invalid data, parsing failure), the server should log the specific error, abort the update, and continue operating with the existing knowledge graph data without degradation.

**Validates: Requirements 19.4**

### Property 17: Build Error Reporting

*For any* failure during the initial build process (missing data files, download failure, database connection failure), the build tool should return a descriptive error message indicating which specific step failed and what action is needed to resolve it.

**Validates: Requirements 23.4**

### Property 18: Build Progress Logging

*For any* build operation (online or offline), the build tool should log progress events including which datasets are being processed, their sizes, processing time, and completion status, enabling administrators to monitor long-running builds.

**Validates: Requirements 23.5**

### Property 19: Agentic Workflow Prompt Availability

*For any* agentic workflow prompt defined in the specification (validate_code_execution_safety, assess_dependency_vulnerabilities, guide_secure_code_generation, analyze_attack_surface, recognize_vulnerability_patterns, discover_exploit_chains, recommend_security_controls, assist_threat_modeling, detect_security_regressions, map_compliance_standards, pre_commit_security_check), the server should expose the prompt via prompts/list and return structured guidance when invoked via prompts/get.

**Validates: Requirements 24.1, 24.2, 25.1, 26.1, 27.1, 28.1, 29.1, 30.1, 31.1, 32.1, 33.1, 34.1, 35.1**

### Property 20: Workflow Prompt Guidance Structure

*For any* agentic workflow prompt invocation, the returned guidance should include: (1) step-by-step instructions for querying BRON, (2) a list of suggested tools to use, (3) a decision framework with risk levels and recommended actions, and (4) examples of patterns to check or avoid.

**Validates: Requirements 24.3, 24.4, 25.2, 25.3, 26.2, 26.3, 27.2, 27.3, 28.2, 28.3, 29.2, 29.3, 30.2, 30.3, 31.2, 31.3, 32.2, 32.3, 33.2, 33.3, 34.2, 34.3, 35.2, 35.3**

### Property 21: Code Safety Validation Guidance

*For any* code snippet provided to the validate_code_execution_safety prompt, the guidance should include instructions for: (1) identifying code patterns that match CWE weaknesses, (2) searching BRON for related CVEs and CAPEC patterns, (3) assessing execution risk based on CWE severity and CVE exploitability, and (4) providing a clear decision framework (EXECUTE/WARN/BLOCK) with reasoning.

**Validates: Requirements 25.2, 25.3, 25.4, 25.5**

### Property 22: Dependency Vulnerability Assessment Guidance

*For any* package name and version provided to the assess_dependency_vulnerabilities prompt, the guidance should include instructions for: (1) searching BRON for CVEs mentioning the package, (2) analyzing CVE severity and version applicability, (3) identifying related CWEs to understand vulnerability types, (4) assessing transitive dependency risks, and (5) recommending safe versions or alternatives.

**Validates: Requirements 26.2, 26.3, 26.4, 26.5**

### Property 23: Secure Code Generation Guidance

*For any* feature description provided to the guide_secure_code_generation prompt, the guidance should include instructions for: (1) identifying security-relevant operations in the feature, (2) querying BRON for CWEs related to those operations, (3) understanding vulnerability patterns through CVE examples, (4) applying secure coding patterns that mitigate identified CWEs, and (5) documenting security assumptions.

**Validates: Requirements 27.2, 27.3, 27.4, 27.5**

### Property 24: Attack Surface Analysis Guidance

*For any* code change description provided to the analyze_attack_surface prompt, the guidance should include instructions for: (1) mapping exposed interfaces to ATT&CK techniques, (2) discovering related CAPEC attack patterns, (3) assessing exploitability based on access requirements, (4) identifying related CVEs for similar attack surfaces, and (5) recommending specific mitigations and security testing.

**Validates: Requirements 28.2, 28.3, 28.4, 28.5**

### Property 25: Vulnerability Pattern Recognition Guidance

*For any* code snippet provided to the recognize_vulnerability_patterns prompt, the guidance should include instructions for: (1) scanning for common vulnerability indicators, (2) mapping identified patterns to specific CWE definitions, (3) assessing severity through related CVEs, (4) distinguishing false positives from genuine vulnerabilities, and (5) providing specific remediation advice with CWE references.

**Validates: Requirements 29.2, 29.3, 29.4, 29.5**

### Property 26: Exploit Chain Discovery Guidance

*For any* set of vulnerability identifiers provided to the discover_exploit_chains prompt, the guidance should include instructions for: (1) building a vulnerability graph through BRON relationships, (2) identifying CAPEC patterns that chain multiple weaknesses, (3) discovering multi-stage attack sequences, (4) mapping to ATT&CK tactics, (5) assessing combined impact, and (6) prioritizing remediation based on which fixes break the most exploit chains.

**Validates: Requirements 30.2, 30.3, 30.4, 30.5**

### Property 27: Security Control Recommendation Guidance

*For any* weakness identifiers provided to the recommend_security_controls prompt, the guidance should include instructions for: (1) understanding the weakness through CWE details, (2) identifying defensive techniques through ATT&CK relationships, (3) mapping to mitigation strategies, (4) providing code-level and architectural mitigations, and (5) prioritizing controls based on effectiveness and implementation cost.

**Validates: Requirements 31.2, 31.3, 31.4, 31.5**

### Property 28: Threat Modeling Assistance Guidance

*For any* system description provided to the assist_threat_modeling prompt, the guidance should include instructions for: (1) identifying attack vectors at trust boundaries, (2) mapping system components to ATT&CK techniques, (3) discovering applicable CAPEC attack patterns, (4) identifying relevant CWEs for the technology stack, (5) generating threat scenarios with likelihood and impact ratings, and (6) defining testable security requirements.

**Validates: Requirements 32.2, 32.3, 32.4, 32.5**

### Property 29: Security Regression Detection Guidance

*For any* code changes provided to the detect_security_regressions prompt, the guidance should include instructions for: (1) identifying previously fixed CWE patterns from historical fixes, (2) analyzing current changes for reintroduction of vulnerable patterns, (3) pattern matching against BRON CWE database, (4) assessing regression risk with confidence levels, (5) providing evidence through code comparisons, and (6) recommending actions (BLOCK/REVIEW/WARN/PASS).

**Validates: Requirements 33.2, 33.3, 33.4, 33.5**

### Property 30: Compliance Standards Mapping Guidance

*For any* vulnerability identifiers provided to the map_compliance_standards prompt, the guidance should include instructions for: (1) understanding vulnerabilities through CVE/CWE details, (2) mapping to common standards (OWASP Top 10, CWE Top 25, PCI-DSS, HIPAA, SOC 2), (3) identifying specific violated requirements, (4) assessing compliance impact severity, (5) prioritizing remediation based on compliance deadlines, and (6) generating audit evidence documentation.

**Validates: Requirements 34.2, 34.3, 34.4, 34.5**

### Property 31: Workflow Prompt Tool Suggestions

*For any* agentic workflow prompt, the prompt response should include a suggested_tools field listing the specific BRON tools (query_cve, query_cwe, query_attack_technique, query_capec, find_relationships, search_bron) that are most relevant for completing the workflow, enabling agents to efficiently query BRON without trial and error.

**Validates: Requirements 24.3, 24.5**

### Property 32: Workflow Decision Framework Consistency

*For any* agentic workflow prompt that requires a decision (validate_code_execution_safety, assess_dependency_vulnerabilities, detect_security_regressions, pre_commit_security_check), the decision framework should consistently define: (1) risk levels (CRITICAL/HIGH/MEDIUM/LOW), (2) possible actions (EXECUTE/WARN/BLOCK or INSTALL/WARN/BLOCK/SUGGEST_ALTERNATIVE or PASS/WARN/BLOCK), and (3) clear criteria for each decision based on BRON query results.

**Validates: Requirements 25.4, 25.7, 26.4, 26.6, 33.4, 33.7, 35.7**

### Property 33: Pre-Commit Security Check Comprehensiveness

*For any* pre-commit security check invocation, the guidance should include instructions for: (1) vulnerability pattern scanning of changed files, (2) dependency checks when package files change, (3) attack surface analysis for new interfaces, (4) regression checks against historical fixes, (5) secrets detection for hardcoded credentials, and (6) a clear decision (BLOCK/WARN/PASS) with reasoning.

**Validates: Requirements 35.2, 35.3, 35.4, 35.5, 35.6, 35.7**

## Error Handling

### Error Categories

The system implements structured error handling across four categories:

**1. Client Errors (4xx-equivalent)**:
- Invalid entity identifiers (malformed CVE-2023-XXXX format)
- Missing required parameters in tool calls
- Invalid resource URIs
- Malformed search queries

**Response**: Return MCP error with code -32602 (Invalid params), include specific validation failure message.

**2. Not Found Errors (404-equivalent)**:
- Entity exists in valid format but not in knowledge graph
- Resource URI points to non-existent entity

**Response**: Return MCP error with code -32001 (custom: entity not found), include entity type and identifier.

**3. Server Errors (5xx-equivalent)**:
- Database connection failures
- Query execution timeouts
- Internal processing errors

**Response**: Return MCP error with code -32603 (Internal error), log full stack trace, return sanitized message to client.

**4. Service Unavailable Errors**:
- Knowledge graph not loaded
- Database unavailable during startup
- System in maintenance mode

**Response**: Return MCP error with code -32002 (custom: service unavailable), include retry guidance.

### Error Handling Patterns

**Database Connection Failures**:
```python
try:
    result = await db_client.execute_query(aql, bind_vars)
except ConnectionError as e:
    logger.error(f"Database connection failed: {e}", exc_info=True)
    raise MCPError(
        code=-32002,
        message="Knowledge graph temporarily unavailable",
        data={"retry_after": 30}
    )
```

**Entity Not Found**:
```python
entity = await query_layer.get_cve(cve_id)
if entity is None:
    raise MCPError(
        code=-32001,
        message=f"CVE not found: {cve_id}",
        data={"entity_type": "cve", "identifier": cve_id}
    )
```

**Invalid Input Validation**:
```python
if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
    raise MCPError(
        code=-32602,
        message=f"Invalid CVE identifier format: {cve_id}",
        data={"expected_format": "CVE-YYYY-NNNNN"}
    )
```

**Graceful Degradation**:
- If full-text search index is unavailable, fall back to exact match queries
- If relationship traversal times out, return partial results with warning
- If export operation fails mid-stream, clean up partial files

### Logging Strategy

**Log Levels**:
- **DEBUG**: Query execution details, parameter values, timing information
- **INFO**: Tool invocations, successful operations, data version changes
- **WARNING**: Degraded performance, fallback operations, retry attempts
- **ERROR**: Failed operations, exceptions, data inconsistencies

**Log Format**:
```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "component": "tool_handler",
  "operation": "query_cve",
  "parameters": {"cve_id": "CVE-2023-1234"},
  "duration_ms": 45,
  "result": "success",
  "client_id": "claude-desktop-abc123"
}
```

**Sensitive Data Handling**:
- Sanitize database credentials from logs
- Redact API keys from error messages
- Limit query result sizes in debug logs

### Retry and Timeout Policies

**Database Queries**:
- Simple queries: 5 second timeout
- Relationship traversal: 30 second timeout
- Full-text search: 10 second timeout
- Retry transient failures up to 3 times with exponential backoff

**Data Updates**:
- Download operations: 5 minute timeout per dataset
- Retry failed downloads up to 3 times
- Abort entire update if any dataset fails after retries

**Client Connections**:
- No timeout on client connections (long-lived stdio transport)
- Individual request timeout: 60 seconds
- Queue requests if processing capacity exceeded

## Testing Strategy

### Dual Testing Approach

The BRON MCP Gateway requires both unit testing and property-based testing to ensure correctness:

**Unit Tests** focus on:
- Specific examples of entity queries (query CVE-2023-1234, query CWE-119)
- MCP protocol handshake sequences (initialize, tools/list, resources/list)
- Error conditions (database unavailable, invalid configuration)
- Integration points (ArangoDB connection, data fetchers)
- Docker deployment verification (container starts, ports exposed)

**Property-Based Tests** focus on:
- Universal properties that hold for all inputs (Properties 1-33 above)
- Comprehensive input coverage through randomization
- Edge cases discovered through generated inputs
- Relationship traversal correctness across random graph structures
- Round-trip properties (export/import, serialize/deserialize)
- Agentic workflow prompt completeness and consistency

### Property-Based Testing Configuration

**Framework**: Use Hypothesis (Python) for property-based testing

**Test Configuration**:
- Minimum 100 iterations per property test (due to randomization)
- Seed-based reproducibility for failed test cases
- Shrinking to find minimal failing examples
- Deadline of 30 seconds per test case

**Test Tagging**: Each property test must reference its design document property:

```python
@given(cve_id=valid_cve_identifiers())
@settings(max_examples=100)
def test_entity_retrieval_completeness(cve_id):
    """
    Feature: bron-mcp-gateway, Property 1: Entity Retrieval Completeness
    
    For any valid CVE identifier in the knowledge graph, querying should
    return complete entity data with all required fields.
    """
    result = query_cve(cve_id)
    assert result is not None
    assert "description" in result
    assert "severity" in result
    assert "related_cwes" in result
    assert "related_attack_techniques" in result
```

### Test Data Strategy

**Test Knowledge Graph**:
- Maintain a small, curated test dataset with known entities and relationships
- Include edge cases: CVEs with no CWE mappings, isolated entities, circular relationships
- Version control test data for reproducibility

**Generators for Property Tests**:
```python
@composite
def valid_cve_identifiers(draw):
    """Generate valid CVE identifiers from test knowledge graph."""
    year = draw(integers(min_value=1999, max_value=2024))
    sequence = draw(integers(min_value=1, max_value=99999))
    return f"CVE-{year}-{sequence}"

@composite
def invalid_cve_identifiers(draw):
    """Generate invalid CVE identifier formats."""
    return draw(one_of(
        text(min_size=1, max_size=20),  # Random strings
        just("CVE-INVALID"),  # Wrong format
        just("CVE-2023"),  # Incomplete
        just("2023-1234"),  # Missing prefix
    ))

@composite
def entity_with_relationships(draw):
    """Generate entity ID that has known relationships in test graph."""
    # Return entity IDs from test data that have relationships
    return draw(sampled_from(TEST_ENTITIES_WITH_RELATIONSHIPS))
```

### Integration Testing

**MCP Protocol Compliance**:
- Use official MCP test suite (if available) to verify protocol compliance
- Test with real MCP clients (Claude Desktop, custom test client)
- Verify stdio transport, JSON-RPC message framing

**Database Integration**:
- Test against real ArangoDB instance (not mocked)
- Verify graph traversal queries return correct results
- Test transaction handling for updates

**Docker Integration**:
- Build and run Docker Compose stack in CI/CD
- Verify container networking (MCP server can reach ArangoDB)
- Test volume persistence (data survives container restart)
- Test all three deployment modes (cloud, on-prem, isolated networks)

### Performance Testing

While not correctness properties, performance tests validate non-functional requirements:

**Load Testing**:
- Simulate 10 concurrent clients making queries
- Verify response times meet requirements (500ms simple, 2s complex)
- Verify no request rejections under normal load

**Stress Testing**:
- Gradually increase load until system saturates
- Verify graceful degradation (queueing, not rejection)
- Verify recovery after load reduction

**Data Scale Testing**:
- Test with full-scale knowledge graph (250k CVEs, 900 CWEs, etc.)
- Verify query performance remains acceptable
- Verify memory usage stays within container limits

### Test Execution Strategy

**Development**:
- Run unit tests on every commit (fast feedback)
- Run property tests nightly (comprehensive coverage)
- Run integration tests on pull requests

**CI/CD Pipeline**:
1. Lint and type checking (mypy, ruff)
2. Unit tests (pytest, <5 minutes)
3. Property-based tests (pytest + Hypothesis, <30 minutes)
4. Integration tests (Docker Compose, <15 minutes)
5. Build and push Docker image (on main branch)

**Pre-Release**:
- Full test suite including performance tests
- Manual testing with Claude Desktop
- Isolated network deployment verification
- Documentation review

### Test Coverage Goals

- Line coverage: >85% for core logic (query layer, tool handlers)
- Branch coverage: >80% for error handling paths
- Property coverage: 100% (all 33 properties must have tests)
- Integration coverage: All three deployment modes tested

