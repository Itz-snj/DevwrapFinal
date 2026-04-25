/**
 * Project Phoenix — PDF Report Generator
 * 
 * Converts Markdown forensic reports to styled PDF using md-to-pdf.
 * Falls back to raw Markdown download if md-to-pdf is unavailable.
 */

import { mdToPdf } from 'md-to-pdf';

export class PdfGenerator {
  constructor() {
    this.cssStyles = `
      body { 
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
        line-height: 1.6; 
        color: #1a1a2e; 
        max-width: 900px;
        margin: 0 auto;
        padding: 40px;
      }
      h1 { 
        color: #0A0A0F; 
        border-bottom: 3px solid #00F0FF; 
        padding-bottom: 12px; 
      }
      h2 { 
        color: #16213e; 
        border-bottom: 1px solid #ddd; 
        padding-bottom: 8px; 
        margin-top: 32px;
      }
      h3 { color: #0f3460; }
      table { 
        border-collapse: collapse; 
        width: 100%; 
        margin: 16px 0; 
        font-size: 13px;
      }
      th { 
        background-color: #16213e; 
        color: white; 
        padding: 10px 12px; 
        text-align: left; 
      }
      td { 
        padding: 8px 12px; 
        border-bottom: 1px solid #e0e0e0; 
      }
      tr:nth-child(even) { background-color: #f8f9fa; }
      code { 
        background-color: #f0f0f0; 
        padding: 2px 6px; 
        border-radius: 3px; 
        font-size: 12px; 
      }
      pre { 
        background-color: #1a1a2e; 
        color: #e0e0e0; 
        padding: 16px; 
        border-radius: 6px; 
        overflow-x: auto; 
        font-size: 12px;
      }
      pre code { background: none; color: inherit; }
      hr { border: none; border-top: 1px solid #ddd; margin: 24px 0; }
      blockquote { 
        border-left: 4px solid #00F0FF; 
        padding-left: 16px; 
        color: #555; 
      }
    `;
  }

  /**
   * Convert Markdown to PDF buffer.
   * @param {string} markdown - Markdown content
   * @returns {Promise<Buffer>} PDF buffer
   */
  async generate(markdown) {
    try {
      const result = await mdToPdf(
        { content: markdown },
        {
          css: this.cssStyles,
          pdf_options: {
            format: 'A4',
            margin: { top: '25mm', bottom: '25mm', left: '20mm', right: '20mm' },
            printBackground: true
          },
          launch_options: {
            args: ['--no-sandbox', '--disable-setuid-sandbox']
          }
        }
      );

      if (result && result.content) {
        return result.content;
      }
      throw new Error('md-to-pdf returned empty content');
    } catch (err) {
      throw new Error(`PDF generation failed: ${err.message}. Falling back to Markdown download.`);
    }
  }
}
