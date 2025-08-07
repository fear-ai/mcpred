"""
Report export functionality.
"""

import logging
import os
from pathlib import Path
from typing import Dict, Any, Optional

from .formatters import BaseFormatter, JSONFormatter, HTMLFormatter, TextFormatter


logger = logging.getLogger(__name__)


class ReportExporter:
    """Export reports in various formats."""
    
    def __init__(self):
        self.formatters = {
            "json": JSONFormatter(),
            "html": HTMLFormatter(),
            "text": TextFormatter(),
            "txt": TextFormatter(),
        }
    
    def export_report(
        self, 
        report_data: Dict[str, Any], 
        output_path: str, 
        format_type: str = "json"
    ) -> str:
        """Export report to file."""
        logger.info(f"Exporting report to {output_path} in {format_type} format")
        
        try:
            formatter = self._get_formatter(format_type)
            formatted_content = formatter.format_report(report_data)
            
            # Ensure output path has correct extension
            output_path = self._ensure_correct_extension(output_path, formatter)
            
            # Create directory if it doesn't exist
            output_dir = Path(output_path).parent
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Write report to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(formatted_content)
            
            logger.info(f"Report exported successfully to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Report export failed: {e}")
            raise
    
    def export_multiple_formats(
        self, 
        report_data: Dict[str, Any], 
        base_path: str, 
        formats: list = None
    ) -> Dict[str, str]:
        """Export report in multiple formats."""
        if formats is None:
            formats = ["json", "html", "text"]
        
        logger.info(f"Exporting report in {len(formats)} formats")
        
        exported_files = {}
        
        for format_type in formats:
            try:
                formatter = self._get_formatter(format_type)
                output_path = base_path + formatter.get_file_extension()
                exported_path = self.export_report(report_data, output_path, format_type)
                exported_files[format_type] = exported_path
            except Exception as e:
                logger.warning(f"Failed to export {format_type} format: {e}")
                exported_files[format_type] = None
        
        return exported_files
    
    def _get_formatter(self, format_type: str) -> BaseFormatter:
        """Get formatter for specified format type."""
        formatter = self.formatters.get(format_type.lower())
        if not formatter:
            available_formats = list(self.formatters.keys())
            raise ValueError(f"Unsupported format '{format_type}'. Available formats: {available_formats}")
        
        return formatter
    
    def _ensure_correct_extension(self, output_path: str, formatter: BaseFormatter) -> str:
        """Ensure output path has correct file extension."""
        expected_ext = formatter.get_file_extension()
        path_obj = Path(output_path)
        
        if path_obj.suffix != expected_ext:
            return str(path_obj.with_suffix(expected_ext))
        
        return output_path
    
    def get_supported_formats(self) -> list:
        """Get list of supported export formats."""
        return list(self.formatters.keys())