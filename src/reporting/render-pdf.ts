// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * HTML → PDF via Playwright headless Chromium. In the Docker image the browser
 * binary is provided at PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH (browser download
 * skipped); honor it when present.
 */

import chalk from 'chalk';

export async function renderPdf(html: string, outPath: string): Promise<void> {
  // Import lazily so environments without Playwright installed don't crash at
  // module load — the caller wraps this in try/catch for non-fatal degradation.
  const { chromium } = await import('playwright');

  const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
  const launchOptions: Parameters<typeof chromium.launch>[0] = {
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  };
  if (executablePath) {
    launchOptions.executablePath = executablePath;
  }

  const browser = await chromium.launch(launchOptions);
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle' });
    await page.pdf({
      path: outPath,
      format: 'A4',
      printBackground: true,
      margin: { top: '12mm', bottom: '14mm', left: '10mm', right: '10mm' },
    });
    console.log(chalk.green(`✅ Wrote PDF: ${outPath}`));
  } finally {
    await browser.close();
  }
}
