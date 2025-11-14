"""
Quick test script to verify backend setup
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")
    
    try:
        from app import create_app
        print("✅ Flask app factory imported")
        
        from app.models.user import User
        from app.models.log_file import LogFile
        from app.models.log_entry import LogEntry
        from app.models.anomaly import Anomaly
        print("✅ All models imported")
        
        from app.repositories.user_repository import UserRepository
        from app.repositories.log_file_repository import LogFileRepository
        from app.repositories.log_entry_repository import LogEntryRepository
        from app.repositories.anomaly_repository import AnomalyRepository
        print("✅ All repositories imported")
        
        from app.services.auth_service import AuthService
        from app.services.file_storage_service import FileStorageService
        from app.services.log_parser_service import LogParserService
        from app.services.anomaly_detection_service import AnomalyDetectionService
        print("✅ All services imported")
        
        from app.parsers.zscaler_parser import ZscalerParser
        print("✅ Parser imported")
        
        from app.controllers.auth_controller import auth_bp
        from app.controllers.upload_controller import upload_bp
        from app.controllers.analysis_controller import analysis_bp
        from app.controllers.anomaly_controller import anomaly_bp
        print("✅ All controllers imported")
        
        return True
    except Exception as e:
        print(f"❌ Import error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_app_creation():
    """Test Flask app creation"""
    print("\nTesting Flask app creation...")
    
    try:
        from app import create_app
        app = create_app('development')
        print(f"✅ Flask app created: {app.name}")
        
        # Test routes
        with app.app_context():
            from flask import url_for
            print(f"✅ App context working")
        
        return True
    except Exception as e:
        print(f"❌ App creation error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_parser():
    """Test Zscaler parser"""
    print("\nTesting Zscaler parser...")
    
    try:
        from app.parsers.zscaler_parser import ZscalerParser
        
        parser = ZscalerParser()
        
        # Test parsing a sample line
        sample_line = 'time="2025-10-31T10:15:23Z" user="john.doe@company.com" src="192.168.1.100" hostname="example.com" url="https://example.com" riskscore="10"'
        
        result = parser.parse_line(sample_line, 1)
        
        if result:
            print(f"✅ Parser working - parsed {len(result)} fields")
            print(f"   Sample fields: username={result.get('username')}, source_ip={result.get('source_ip')}")
            return True
        else:
            print("❌ Parser returned None")
            return False
            
    except Exception as e:
        print(f"❌ Parser error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("CyberDucky Mini SIEM - Backend Setup Test")
    print("=" * 60)
    
    results = []
    
    results.append(("Imports", test_imports()))
    results.append(("App Creation", test_app_creation()))
    results.append(("Parser", test_parser()))
    
    print("\n" + "=" * 60)
    print("Test Results:")
    print("=" * 60)
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name}: {status}")
    
    all_passed = all(result[1] for result in results)
    
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 All tests passed! Backend is ready.")
        print("\nNext steps:")
        print("1. Set up PostgreSQL database")
        print("2. Update .env with database credentials")
        print("3. Run: flask init-db")
        print("4. Run: python run.py")
    else:
        print("⚠️ Some tests failed. Please fix the errors above.")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == '__main__':
    sys.exit(main())

