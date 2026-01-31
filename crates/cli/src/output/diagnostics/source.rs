//! Source file caching and line extraction
//!
//! Provides efficient access to source files for diagnostic rendering.
//! Files are cached after first read to avoid repeated I/O.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A single line of source code
#[derive(Debug, Clone)]
pub struct SourceLine {
    /// Line number (1-indexed)
    pub number: usize,
    /// The content of the line (without newline)
    pub content: String,
    /// Byte offset of the line start in the original content
    pub byte_offset: usize,
}

/// A cached source file with pre-split lines
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Path to the source file
    pub path: PathBuf,
    /// Original content
    pub content: String,
    /// Pre-split lines for fast access
    lines: Vec<SourceLine>,
}

impl SourceFile {
    /// Create a new SourceFile from path and content
    pub fn new(path: PathBuf, content: String) -> Self {
        let lines = Self::split_lines(&content);
        Self {
            path,
            content,
            lines,
        }
    }

    /// Load a source file from disk
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(Self::new(path.to_path_buf(), content))
    }

    /// Get a line by number (1-indexed)
    pub fn get_line(&self, line_number: usize) -> Option<&SourceLine> {
        if line_number == 0 || line_number > self.lines.len() {
            None
        } else {
            Some(&self.lines[line_number - 1])
        }
    }

    /// Get a range of lines (1-indexed, inclusive)
    pub fn get_lines(&self, start: usize, end: usize) -> Vec<&SourceLine> {
        let start = start.saturating_sub(1);
        let end = end.min(self.lines.len());
        self.lines[start..end].iter().collect()
    }

    /// Total number of lines
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Split content into lines with metadata
    fn split_lines(content: &str) -> Vec<SourceLine> {
        let mut lines = Vec::new();
        let mut byte_offset = 0;

        for (idx, line) in content.lines().enumerate() {
            lines.push(SourceLine {
                number: idx + 1,
                content: line.to_string(),
                byte_offset,
            });
            // +1 for the newline character
            byte_offset += line.len() + 1;
        }

        lines
    }

    /// Convert line/column to byte offset
    pub fn line_col_to_offset(&self, line: usize, col: usize) -> usize {
        if let Some(source_line) = self.get_line(line) {
            source_line.byte_offset + col.saturating_sub(1)
        } else {
            0
        }
    }
}

/// Cache for source files to avoid repeated disk reads
#[derive(Debug, Default)]
pub struct SourceCache {
    cache: HashMap<PathBuf, Arc<SourceFile>>,
}

impl SourceCache {
    /// Create a new empty cache
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Get a source file, loading from disk if not cached
    pub fn get(&mut self, path: &Path) -> Option<Arc<SourceFile>> {
        // Return cached if available
        if let Some(source) = self.cache.get(path) {
            return Some(Arc::clone(source));
        }

        // Try to load from disk
        match SourceFile::load(path) {
            Ok(source) => {
                let source = Arc::new(source);
                self.cache.insert(path.to_path_buf(), Arc::clone(&source));
                Some(source)
            }
            Err(_) => None,
        }
    }

    /// Pre-populate the cache with a source file (useful when content is already in memory)
    pub fn insert(&mut self, path: PathBuf, content: String) {
        let source = Arc::new(SourceFile::new(path.clone(), content));
        self.cache.insert(path, source);
    }

    /// Clear the cache
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Number of cached files
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_file_lines() {
        let content = "line 1\nline 2\nline 3";
        let source = SourceFile::new(PathBuf::from("test.rs"), content.to_string());

        assert_eq!(source.line_count(), 3);
        assert_eq!(source.get_line(1).unwrap().content, "line 1");
        assert_eq!(source.get_line(2).unwrap().content, "line 2");
        assert_eq!(source.get_line(3).unwrap().content, "line 3");
        assert!(source.get_line(0).is_none());
        assert!(source.get_line(4).is_none());
    }

    #[test]
    fn test_source_file_byte_offsets() {
        let content = "abc\ndef\nghi";
        let source = SourceFile::new(PathBuf::from("test.rs"), content.to_string());

        assert_eq!(source.get_line(1).unwrap().byte_offset, 0);
        assert_eq!(source.get_line(2).unwrap().byte_offset, 4); // "abc\n" = 4 bytes
        assert_eq!(source.get_line(3).unwrap().byte_offset, 8); // "abc\ndef\n" = 8 bytes
    }

    #[test]
    fn test_line_col_to_offset() {
        let content = "hello world\nfoo bar";
        let source = SourceFile::new(PathBuf::from("test.rs"), content.to_string());

        assert_eq!(source.line_col_to_offset(1, 1), 0);
        assert_eq!(source.line_col_to_offset(1, 7), 6); // 'w' in "world"
        assert_eq!(source.line_col_to_offset(2, 1), 12); // 'f' in "foo"
        assert_eq!(source.line_col_to_offset(2, 5), 16); // 'b' in "bar"
    }

    #[test]
    fn test_source_cache() {
        let mut cache = SourceCache::new();
        cache.insert(PathBuf::from("test.rs"), "content".to_string());

        assert_eq!(cache.len(), 1);
        assert!(cache.get(Path::new("test.rs")).is_some());
        assert!(cache.get(Path::new("nonexistent.rs")).is_none());
    }

    #[test]
    fn test_get_lines_range() {
        let content = "a\nb\nc\nd\ne";
        let source = SourceFile::new(PathBuf::from("test.rs"), content.to_string());

        let lines = source.get_lines(2, 4);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].content, "b");
        assert_eq!(lines[1].content, "c");
        assert_eq!(lines[2].content, "d");
    }
}
