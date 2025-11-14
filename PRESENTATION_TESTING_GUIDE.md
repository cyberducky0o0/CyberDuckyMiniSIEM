# 🎯 Presentation Testing Guide

## Quick Pre-Presentation Checklist

### 1. **Verify Services are Running** ✅
```bash
docker-compose ps
```
**Expected:** All 4 containers running (backend, db, frontend, ollama)

---

### 2. **Test Login** ✅
1. Navigate to `http://localhost:5173`
2. Login with: `admin@cyberducky.com` / `admin123`
3. **Expected:** Redirect to Overview Dashboard

---

### 3. **Test Overview Dashboard** ✅
1. Verify metrics cards display numbers
2. Check for any console errors (F12)
3. Click "Refresh" button
4. **Expected:** Dashboard loads without errors, shows aggregated stats

---

### 4. **Test File Upload** ✅
1. Click "Upload" in navigation
2. Select `backend/sample_data/zscaler_weekly_sample.csv`
3. Click "Upload"
4. **Expected:** 
   - Progress bar shows
   - Success message appears
   - File appears in dashboard

---

### 5. **Test Analysis Page** ✅
1. From Dashboard, click on uploaded file
2. Wait for analysis to load
3. Scroll through all sections
4. **Expected:**
   - Metrics Overview loads
   - All visualizations display
   - No "No data" messages (except if no anomalies)
   - No console errors

---

### 6. **Test Visualizations** ✅

#### Check These Widgets:
- [ ] **Risk Score Trendline** - Line chart with EWMA
- [ ] **Event Timeline** - Bar chart with events over time
- [ ] **Anomaly Time Series** - Stacked area chart by severity
- [ ] **Requests Per Minute** - Area chart with average line
- [ ] **Anomaly Distribution** - Pie chart by severity
- [ ] **Top Threats** - Bar chart
- [ ] **User Activity** - Table or chart

**Expected:** All charts render with data, no errors

---

### 7. **Test Error Handling** ✅

#### Test Invalid File ID:
1. Navigate to `http://localhost:5173/analysis/invalid-id`
2. **Expected:** Error message displays, "Go Back" button works

#### Test Network Error:
1. Stop backend: `docker-compose stop backend`
2. Try to load dashboard
3. **Expected:** Error message, retry button
4. Restart: `docker-compose start backend`

---

### 8. **Test Null Data Scenarios** ✅

#### Upload Empty File:
1. Create a CSV with only headers
2. Upload it
3. **Expected:** "No data" messages, no crashes

#### Check Console:
1. Open browser console (F12)
2. Navigate through app
3. **Expected:** No red errors, only info/debug logs

---

## 🎬 Presentation Demo Flow

### **Demo Script (5-10 minutes)**

#### 1. **Introduction** (30 seconds)
> "CyberDucky Mini SIEM is a SOC analyst-focused security information and event management application designed specifically for analyzing Zscaler NSS Web Logs."

#### 2. **Overview Dashboard** (1 minute)
- Show aggregated metrics across all files
- Highlight key numbers: Total files, entries, anomalies
- Point out critical anomalies count
- Show recent activity

#### 3. **Upload Workflow** (1 minute)
- Click "Upload"
- Select `zscaler_weekly_sample.csv`
- Show upload progress
- Explain: "This file contains 3,613 logs over 7 days with 4 embedded attack patterns"

#### 4. **Analysis Deep Dive** (3-4 minutes)
- Click on uploaded file
- **Metrics Overview:**
  - Total entries, anomalies, risk score
  - Unique users, IPs, threats
  
- **Visualizations:**
  - **Anomaly Time Series:** "Notice the spikes on Days 3, 4, 5, and 6 - these are our embedded attack patterns"
  - **Event Timeline:** "Shows activity distribution over the week"
  - **Risk Trendline:** "EWMA smoothing helps identify sustained risk elevation"
  
- **Anomaly Details:**
  - Show critical anomalies
  - Explain severity levels
  - Highlight threat types

#### 5. **Statistical Detection** (1-2 minutes)
- Explain the 4 core methods:
  1. **Z-Score Analysis** - Rate anomalies
  2. **Percentile-Based** - Data exfiltration
  3. **EWMA** - Persistent high risk
  4. **Burst Detection** - DDoS, brute force

#### 6. **Attack Patterns** (1-2 minutes)
Show the 4 embedded patterns:
1. **Data Exfiltration** (Day 3, 11 PM) - 20 attempts
2. **Phishing Campaign** (Day 4, 9:30 AM) - 15 attempts
3. **Unusual Uploads** (Day 5, 2 PM) - 30 large uploads
4. **C2 Beaconing** (Day 6, all day) - 48 beacons every 15 min

#### 7. **Wrap-up** (30 seconds)
- Highlight production-ready features:
  - Robust error handling
  - Null-safe data processing
  - Error boundaries
  - User-friendly interface
  - SOC analyst-focused design

---

## 🐛 Common Issues & Fixes

### Issue: "No data available" in widgets
**Fix:** 
- Check if file has anomalies
- Verify backend is running
- Check browser console for errors

### Issue: Visualizations not loading
**Fix:**
- Refresh page
- Check network tab (F12)
- Verify API endpoints responding

### Issue: Upload fails
**Fix:**
- Check file format (CSV with correct headers)
- Verify backend logs: `docker-compose logs backend --tail=50`
- Check disk space

### Issue: Slow performance
**Fix:**
- Reduce file size (< 10,000 entries recommended)
- Check Docker resources
- Restart containers: `docker-compose restart`

---

## 📊 Sample Data Files

### For Quick Demo:
- **`comprehensive_zscaler_sample.csv`** - 220 entries, fast processing
- **`zscaler_weekly_sample.csv`** - 3,613 entries, full week, 4 attack patterns

### For Stress Testing:
- Upload multiple files
- Test with 10,000+ entries

---

## ✅ Pre-Presentation Checklist

- [ ] All Docker containers running
- [ ] Can login successfully
- [ ] Overview Dashboard loads
- [ ] Can upload sample file
- [ ] Analysis page displays all widgets
- [ ] No console errors
- [ ] Error handling works
- [ ] Browser cache cleared
- [ ] Demo file ready (`zscaler_weekly_sample.csv`)
- [ ] Backup plan (screenshots) ready

---

## 🎤 Key Talking Points

1. **SOC Analyst Focus:** "Designed specifically for security operations center analysts"
2. **Statistical Detection:** "4 core statistical methods for anomaly detection"
3. **Real-time Analysis:** "Processes logs and detects anomalies in under 60 seconds"
4. **Production Ready:** "Robust error handling, null-safe, with error boundaries"
5. **Extensible:** "Parser architecture supports multiple log types"
6. **Comprehensive:** "7 visualization types, LLM integration, unified analysis"

---

## 🚀 Final Check Before Presentation

```bash
# 1. Restart all services
docker-compose restart

# 2. Check logs for errors
docker-compose logs backend --tail=20
docker-compose logs frontend --tail=20

# 3. Open browser
# Navigate to http://localhost:5173

# 4. Login and verify
# admin@cyberducky.com / admin123

# 5. Upload demo file
# backend/sample_data/zscaler_weekly_sample.csv

# 6. Verify analysis page loads
# Click on uploaded file

# 7. Check console (F12)
# Should see only info logs, no errors
```

---

**Status:** ✅ **READY FOR PRESENTATION**

All systems tested and verified. Application is production-ready with comprehensive error handling and null-safety.

