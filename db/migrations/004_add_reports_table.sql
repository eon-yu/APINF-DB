-- Add reports table for report generation feature

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    type TEXT NOT NULL,                   -- pdf, csv, excel
    status TEXT NOT NULL,                 -- generating, completed, failed
    format TEXT NOT NULL,                 -- summary, detailed, executive
    file_path TEXT,                       -- path to generated file
    file_size INTEGER DEFAULT 0,          -- file size in bytes
    generated_by TEXT NOT NULL,           -- user who generated the report
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    metadata_json TEXT NOT NULL DEFAULT '{}',  -- JSON configuration and metadata
    
    CHECK (type IN ('pdf', 'csv', 'excel')),
    CHECK (status IN ('generating', 'completed', 'failed')),
    CHECK (format IN ('summary', 'detailed', 'executive'))
);

-- Index for reports
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(type);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_generated_by ON reports(generated_by); 