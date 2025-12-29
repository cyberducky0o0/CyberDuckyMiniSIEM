# CyberDucky Mini SIEM - Documentation Index

Welcome to the CyberDucky Mini SIEM documentation! This folder contains comprehensive guides for developers, SOC analysts, and system administrators.

---

##  Documentation Structure

###  Architecture

**[SYSTEM_ARCHITECTURE.md](architecture/SYSTEM_ARCHITECTURE.md)**
- High-level system architecture
- Design patterns (MVC, Repository, Service Layer, Strategy, Factory)
- Component interactions
- Data flow diagrams
- Technology stack details

**Topics Covered:**
- Backend architecture (Flask, SQLAlchemy, PostgreSQL)
- Frontend architecture (React, TypeScript, Vite)
- Database schema and relationships
- API design and REST principles
- Service layer organization
- Parser extensibility

---

###  Guides

**[SOC_ANALYST_GUIDE.md](guides/SOC_ANALYST_GUIDE.md)**
- Quick start for SOC analysts
- How to upload and analyze logs
- Investigation workflows
- Anomaly types and severity levels
- Detection methods explained
- Common scenarios and responses
- Tips and tricks

**[PARSER_GUIDE.md](guides/PARSER_GUIDE.md)**
- Parser architecture overview
- How parsers work
- Zscaler parser implementation
- Field mapping reference
- How to add new log sources (CrowdStrike, Okta, AWS, etc.)
- Step-by-step parser creation guide

**[ANOMALY_DETECTION.md](guides/ANOMALY_DETECTION.md)**
- Detection pipeline overview
- Rule-based detection methods
- Statistical detection algorithms
- LLM-based detection
- Detection confidence scoring
- Anomaly severity levels

**[SAMPLE_DATA.md](guides/SAMPLE_DATA.md)**
- Sample data overview
- User scenarios (compromised account, data exfiltration, insider threat)
- Expected metrics and anomalies
- Investigation workflows
- How to upload sample data
- Learning objectives

---

###  Deployment

**[DOCKER_DEPLOYMENT.md](deployment/DOCKER_DEPLOYMENT.md)**
- Docker Compose configuration
- Environment variables
- Volume mounts
- Common commands
- Troubleshooting guide
- Production deployment checklist
- Security best practices

---

##  Quick Links by Role

### For SOC Analysts

1. **Getting Started**
   - [SOC Analyst Guide](guides/SOC_ANALYST_GUIDE.md) - Start here!
   - [Sample Data](guides/SAMPLE_DATA.md) - Practice with sample logs

2. **Investigation**
   - [Anomaly Detection](guides/ANOMALY_DETECTION.md) - Understand detection methods
   - [SOC Analyst Guide - Investigation Workflows](guides/SOC_ANALYST_GUIDE.md#investigation-workflow)

3. **Reference**
   - [Anomaly Types](guides/SOC_ANALYST_GUIDE.md#anomaly-types)
   - [Common Scenarios](guides/SOC_ANALYST_GUIDE.md#common-scenarios)

### For Developers

1. **Architecture**
   - [System Architecture](architecture/SYSTEM_ARCHITECTURE.md) - Understand the system
   - [Parser Guide](guides/PARSER_GUIDE.md) - Add new log sources

2. **Development**
   - [Docker Deployment](deployment/DOCKER_DEPLOYMENT.md) - Local development setup
   - [Anomaly Detection](guides/ANOMALY_DETECTION.md) - Detection algorithms

3. **Testing**
   - [Sample Data](guides/SAMPLE_DATA.md) - Test data for development

### For System Administrators

1. **Deployment**
   - [Docker Deployment](deployment/DOCKER_DEPLOYMENT.md) - Production deployment
   - [System Architecture](architecture/SYSTEM_ARCHITECTURE.md) - Infrastructure requirements

2. **Operations**
   - [Docker Deployment - Troubleshooting](deployment/DOCKER_DEPLOYMENT.md#troubleshooting)
   - [Docker Deployment - Common Commands](deployment/DOCKER_DEPLOYMENT.md#common-commands)

3. **Security**
   - [Docker Deployment - Production Deployment](deployment/DOCKER_DEPLOYMENT.md#production-deployment)
   - [Docker Deployment - Security Checklist](deployment/DOCKER_DEPLOYMENT.md#security-checklist)

---

##  Documentation Roadmap

### Current Documentation (v1.0)

-  System Architecture
-  SOC Analyst Guide
-  Parser Guide
-  Anomaly Detection Guide
-  Sample Data Guide
-  Docker Deployment Guide

### Future Documentation (Planned)

- ⏳ API Reference (detailed endpoint documentation)
- ⏳ Database Schema Guide (detailed table and relationship documentation)
- ⏳ Frontend Development Guide (component architecture, state management)
- ⏳ Testing Guide (unit tests, integration tests, E2E tests)
- ⏳ Performance Tuning Guide (optimization tips, scaling strategies)
- ⏳ Backup and Recovery Guide (database backups, disaster recovery)

---

##  Contributing to Documentation

If you find errors or want to improve the documentation:

1. **For Typos/Errors**: Create an issue or submit a pull request
2. **For New Guides**: Propose the topic in an issue first
3. **For Updates**: Keep documentation in sync with code changes

**Documentation Standards:**
- Use Markdown format
- Include code examples where applicable
- Add diagrams for complex concepts
- Keep language clear and concise
- Target specific audiences (analyst, developer, admin)

---

##  Support

For questions not covered in the documentation:

1. Check the main [README.md](../README.md)
2. Review the relevant guide in this folder
3. Check the code comments in the source files
4. Create an issue on GitHub (if applicable)

---

**Last Updated:** 2025-11-12  
**Version:** 1.0  
**Maintained by:** CyberDucky Team


