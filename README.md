# VM-Analysis-Tool

Open-source vulnerability management analysis and prioritization tooling for reviewing CVE, CVSS, EPSS, and KEV data in one place.

## Overview

VM Analysis Tool is a web-based project for security teams, vulnerability management analysts, and defenders who need a faster way to review vulnerability context during triage.

The app is designed to:

- search by CVE ID or keyword
- pull live data from NVD, FIRST EPSS, and CISA KEV
- present a modular one-page CVE analysis
- provide a quick assessment section for operator judgment and remediation decisions

The repository also includes a standalone `index.html` static demo for UI review on static hosts.

## Features

- Live CVE search against NVD
- One-page CVE detail view with:
  - CVE overview
  - CVSS details
  - EPSS enrichment
  - KEV status
  - combined assessment guidance
  - canonical source references
- Modular card-based UI for easy future expansion
- Standalone static HTML demo for simple hosting and previews
- Test scaffolding for adapter normalization and aggregation logic

## Data Sources

The live application is built around these public sources:

- NVD CVE API 2.0 for CVE metadata and CVSS
- FIRST EPSS API for exploitation probability
- CISA Known Exploited Vulnerabilities catalog for exploitation-in-the-wild tracking

## Project Structure

- `app/`: Next.js App Router pages and API routes
- `components/`: UI components and analysis cards
- `lib/`: adapters, types, services, utilities, and demo data
- `tests/`: initial Vitest coverage
- `index.html`: static demo UI for simple local/static hosting

## Running Locally

Requirements:

- Node.js 18 or newer
- npm

Setup:

1. Install dependencies:

   ```bash
   npm install
   ```

2. Start the development server:

   ```bash
   npm run dev
   ```

3. Open:

- `http://localhost:3000/` for the live Next.js app
- `http://localhost:3000/demo` for the bundled demo page

## Environment Variables

Optional:

- `NVD_API_KEY`
- `REQUEST_TIMEOUT_MS`

Example:

```bash
cp .env.example .env.local
```

## Static Demo

The root `index.html` file is a standalone demo UI that works without Node.js, a backend, or build tooling.

Use it when you want:

- a simple visual preview
- quick localhost browser testing
- static hosting on platforms such as GitHub Pages

Important:

- `index.html` is demo-data driven
- live API aggregation does not run in the static demo
- live NVD, EPSS, and KEV ingestion requires the Next.js app and server routes

## Deploying

### Vercel

This project is designed to deploy cleanly on Vercel as a Next.js application.

Typical flow:

1. Import the GitHub repository into Vercel
2. Set any optional environment variables
3. Deploy the project

### Static Hosting

If you only want the UI preview, host the root `index.html` on a static host.

This is not the live production mode.

## API Routes

The live application exposes internal routes:

- `GET /api/search?q=<query>`
- `GET /api/cve/<CVE-ID>`

These routes normalize upstream data for the frontend.

## Development Notes

- The UI is intentionally modular so additional sources or scoring models can be added later
- References are restricted to canonical CVE/NVD, EPSS/FIRST, and KEV/CISA source links
- The current assessment section provides initial operator guidance and can be tuned further for your workflow

## Testing

Run the test suite with:

```bash
npm test
```

## Contributing

Issues and pull requests are welcome.

If you contribute:

- keep the UI modular
- preserve stable response shapes in the internal API layer
- isolate upstream source logic inside adapters

## License

No license file is currently included in this repository.

If you intend this project to be publicly reusable, add a license such as MIT, Apache-2.0, or GPL before inviting outside contributions.
