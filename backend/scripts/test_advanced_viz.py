#!/usr/bin/env python3
"""
Test script to verify advanced visualization endpoints are working
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from app.repositories.log_file_repository import LogFileRepository
from app.services.visualization_data_service import VisualizationDataService

def test_advanced_visualizations():
    """Test advanced visualization data generation"""
    app = create_app()
    
    with app.app_context():
        log_file_repo = LogFileRepository()
        viz_service = VisualizationDataService()
        
        # Get all log files
        print("\n" + "="*80)
        print("TESTING ADVANCED VISUALIZATIONS")
        print("="*80)
        
        # Get all log files from database
        from app.models.log_file import LogFile
        log_files = LogFile.query.all()
        
        print(f"\nFound {len(log_files)} log files in database:")
        for lf in log_files:
            print(f"  - {lf.id}: {lf.original_filename} ({lf.status}) - {lf.parsed_entries} entries")
        
        if not log_files:
            print("\n❌ No log files found! Please upload a log file first.")
            return
        
        # Test with the most recent file
        log_file = log_files[0]
        print(f"\n📊 Testing visualizations for: {log_file.original_filename}")
        print(f"   File ID: {log_file.id}")
        print(f"   Status: {log_file.status}")
        print(f"   Entries: {log_file.parsed_entries}")
        
        # Test each visualization
        visualizations = [
            ('z_score_heatmap', 'Z-Score Heatmap'),
            ('boxplot_per_user', 'Box Plot Per User'),
            ('density_plot', 'Density Plot'),
            ('anomaly_scatter', 'Anomaly Scatter Plot'),
        ]
        
        results = {}
        
        for viz_key, viz_name in visualizations:
            print(f"\n🔍 Testing {viz_name}...")
            try:
                method = getattr(viz_service, f'get_{viz_key}')
                data = method(log_file.id)
                
                if data and 'data' in data and len(data['data']) > 0:
                    print(f"   ✅ SUCCESS: {len(data['data'])} data points")
                    results[viz_key] = data
                else:
                    print(f"   ⚠️  WARNING: No data returned")
                    results[viz_key] = None
                    
            except Exception as e:
                print(f"   ❌ ERROR: {str(e)}")
                results[viz_key] = None
        
        # Summary
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        
        success_count = sum(1 for v in results.values() if v is not None)
        total_count = len(visualizations)
        
        print(f"\n✅ {success_count}/{total_count} visualizations working")
        
        if success_count == 0:
            print("\n❌ No visualizations are working!")
            print("   Possible issues:")
            print("   1. No log entries in the database")
            print("   2. No anomalies detected")
            print("   3. Insufficient data for statistical analysis")
        elif success_count < total_count:
            print("\n⚠️  Some visualizations are not working:")
            for viz_key, viz_name in visualizations:
                if results[viz_key] is None:
                    print(f"   - {viz_name}")
        else:
            print("\n🎉 All visualizations are working!")
        
        # Test the combined endpoint
        print("\n" + "="*80)
        print("TESTING COMBINED ENDPOINT")
        print("="*80)
        
        try:
            all_viz = viz_service.get_all_visualizations(log_file.id)
            print(f"\n✅ Combined endpoint returned {len(all_viz)} visualizations")
            
            for key, value in all_viz.items():
                if value and 'data' in value and len(value['data']) > 0:
                    print(f"   ✅ {key}: {len(value['data'])} data points")
                else:
                    print(f"   ⚠️  {key}: No data")
                    
        except Exception as e:
            print(f"\n❌ Combined endpoint failed: {str(e)}")

if __name__ == '__main__':
    test_advanced_visualizations()

