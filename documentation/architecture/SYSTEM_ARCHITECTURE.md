# CyberDucky Mini SIEM - System Architecture

## Overview

CyberDucky Mini SIEM is a full-stack web application built with a modern, scalable architecture designed for SOC analysts to analyze security logs with AI-powered threat detection.

## High-Level Architecture

```

                    Client (Browser)                          
                  React + TypeScript                          

                      HTTPS/REST API
                      JWT Authentication

                   API Gateway (Flask)                        
                   - CORS Middleware                          
                   - JWT Verification                         
                   - Request Validation                       

                     

                  Controller Layer                            
  - AuthController                                            
  - DashboardController                                       
  - AnalysisController                                        
  - UploadController                                          
  - VisualizationController                                   

                     

                   Service Layer                              
  - LogProcessingService                                      
  - AnomalyDetectionService                                   
  - EnrichmentService                                         
  - StatisticalService                                        
  - LLMService                                                

                     

                  Repository Layer                            
  - UserRepository                                            
  - LogFileRepository                                         
  - LogEntryRepository                                        
  - AnomalyRepository                                         

                     

                PostgreSQL Database                           
  - users                                                     
  - log_files                                                 
  - log_entries                                               
  - anomalies                                                 

```

## Design Patterns

### 1. MVC (Model-View-Controller)

**Models** (`backend/app/models/`)
- SQLAlchemy ORM models
- Represent database tables
- Define relationships and constraints

**Views** (`frontend/src/pages/`)
- React components
- User interface
- Data presentation

**Controllers** (`backend/app/controllers/`)
- Flask blueprints
- Handle HTTP requests
- Route to appropriate services

### 2. Repository Pattern

**Purpose**: Abstract data access logic from business logic

**Implementation**:
```python
class LogFileRepository:
    def get_by_id(self, file_id: str) -> LogFile:
        return LogFile.query.filter_by(id=file_id).first()
    
    def get_by_user(self, user_id: str) -> List[LogFile]:
        return LogFile.query.filter_by(user_id=user_id).all()
    
    def create(self, log_file: LogFile) -> LogFile:
        db.session.add(log_file)
        db.session.commit()
        return log_file
```

**Benefits**:
- Easy to test (mock repositories)
- Centralized data access
- Consistent query patterns

### 3. Service Layer Pattern

**Purpose**: Encapsulate business logic

**Implementation**:
```python
class LogProcessingService:
    def __init__(self):
        self.parser_factory = ParserFactory()
        self.anomaly_service = AnomalyDetectionService()
        self.enrichment_service = EnrichmentService()
    
    def process_file(self, file_path: str, log_type: str):
        parser = self.parser_factory.get_parser(log_type)
        entries = parser.parse_file(file_path)
        
        for entry in entries:
            enriched = self.enrichment_service.enrich(entry)
            anomalies = self.anomaly_service.detect(enriched)
            self.save_entry_and_anomalies(enriched, anomalies)
```

**Benefits**:
- Reusable across controllers
- Testable in isolation
- Clear separation of concerns

### 4. Strategy Pattern (Parsers)

**Purpose**: Extensible log parsing

**Implementation**:
```python
class BaseParser(ABC):
    @abstractmethod
    def parse_line(self, line: str) -> Dict:
        pass

class ZscalerParser(BaseParser):
    def parse_line(self, line: str) -> Dict:
        # Zscaler-specific parsing
        pass

class ParserFactory:
    _parsers = {
        'zscaler': ZscalerParser,
        # Easy to add: 'crowdstrike': CrowdStrikeParser
    }
```

**Benefits**:
- Easy to add new log sources
- Polymorphic behavior
- Testable parsers

### 5. Factory Pattern

**Purpose**: Create appropriate parser instances

**Implementation**:
```python
parser = ParserFactory.get_parser(log_type='zscaler')
# or auto-detect
parser = ParserFactory.get_parser(file_path='/path/to/log.csv')
```

## Component Interactions

### Log Upload Flow

```
User uploads file
    ↓
UploadController receives file
    ↓
LogProcessingService.process_file()
    ↓
ParserFactory.get_parser() → ZscalerParser
    ↓
ZscalerParser.parse_file() → List[Dict]
    ↓
For each entry:
    EnrichmentService.enrich() → NormalizedEvent
    AnomalyDetectionService.detect() → List[Anomaly]
    LogEntryRepository.create()
    AnomalyRepository.create_many()
    ↓
Update LogFile status
    ↓
Return success response
```


