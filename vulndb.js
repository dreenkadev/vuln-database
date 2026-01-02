#!/usr/bin/env node

/*
 * Vulnerability Database - Local CVE database with search
 *
 * Features:
 * - CVE search
 * - CVSS scoring
 * - Vendor filtering
 * - Severity classification
 * - Export functionality
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const VERSION = '1.0.0';

const colors = {
    red: (s) => `\x1b[31m${s}\x1b[0m`,
    green: (s) => `\x1b[32m${s}\x1b[0m`,
    yellow: (s) => `\x1b[33m${s}\x1b[0m`,
    cyan: (s) => `\x1b[36m${s}\x1b[0m`,
    bold: (s) => `\x1b[1m${s}\x1b[0m`,
    dim: (s) => `\x1b[2m${s}\x1b[0m`
};

// Sample CVE data
const sampleCVEs = [
    {
        id: 'CVE-2024-0001',
        description: 'Remote code execution vulnerability in Example Server',
        vendor: 'Example Corp',
        product: 'Example Server',
        cvss: 9.8,
        severity: 'critical',
        published: '2024-01-10',
        references: ['https://example.com/advisory/2024-001']
    },
    {
        id: 'CVE-2024-0002',
        description: 'SQL injection in login module',
        vendor: 'WebApp Inc',
        product: 'WebApp CMS',
        cvss: 8.1,
        severity: 'high',
        published: '2024-01-08',
        references: ['https://webapp.example/security/2024-001']
    },
    {
        id: 'CVE-2024-0003',
        description: 'Cross-site scripting in user profile page',
        vendor: 'SocialNet',
        product: 'SocialNet Platform',
        cvss: 6.1,
        severity: 'medium',
        published: '2024-01-05',
        references: ['https://socialnet.example/cve-2024-0003']
    },
    {
        id: 'CVE-2024-0004',
        description: 'Denial of service via malformed request',
        vendor: 'Example Corp',
        product: 'Example Server',
        cvss: 7.5,
        severity: 'high',
        published: '2024-01-03',
        references: ['https://example.com/advisory/2024-002']
    },
    {
        id: 'CVE-2024-0005',
        description: 'Information disclosure in API endpoint',
        vendor: 'API Services',
        product: 'REST Gateway',
        cvss: 5.3,
        severity: 'medium',
        published: '2024-01-01',
        references: ['https://api.example/security-advisory-jan24']
    },
    {
        id: 'CVE-2023-50001',
        description: 'Buffer overflow in image processing library',
        vendor: 'ImageLib',
        product: 'ImageLib Core',
        cvss: 9.1,
        severity: 'critical',
        published: '2023-12-20',
        references: ['https://imagelib.org/security/CVE-2023-50001']
    },
    {
        id: 'CVE-2023-50002',
        description: 'Authentication bypass in admin panel',
        vendor: 'AdminTools',
        product: 'Admin Dashboard',
        cvss: 9.8,
        severity: 'critical',
        published: '2023-12-15',
        references: ['https://admintools.io/advisory/2023-12']
    },
    {
        id: 'CVE-2023-50003',
        description: 'Path traversal vulnerability',
        vendor: 'FileManager',
        product: 'FileManager Pro',
        cvss: 7.2,
        severity: 'high',
        published: '2023-12-10',
        references: ['https://filemanager.example/sec/CVE-2023-50003']
    }
];

class VulnDB {
    constructor() {
        this.cves = [...sampleCVEs];
        this.dbPath = './vulndb.json';
    }

    load() {
        if (fs.existsSync(this.dbPath)) {
            try {
                const data = JSON.parse(fs.readFileSync(this.dbPath, 'utf8'));
                this.cves = data.cves || sampleCVEs;
            } catch (e) {
                this.cves = sampleCVEs;
            }
        }
    }

    save() {
        fs.writeFileSync(this.dbPath, JSON.stringify({ cves: this.cves }, null, 2));
    }

    search(query, options = {}) {
        let results = this.cves;

        // Text search
        if (query) {
            const q = query.toLowerCase();
            results = results.filter(cve =>
                cve.id.toLowerCase().includes(q) ||
                cve.description.toLowerCase().includes(q) ||
                cve.vendor.toLowerCase().includes(q) ||
                cve.product.toLowerCase().includes(q)
            );
        }

        // Severity filter
        if (options.severity) {
            results = results.filter(cve => cve.severity === options.severity);
        }

        // Vendor filter
        if (options.vendor) {
            results = results.filter(cve =>
                cve.vendor.toLowerCase().includes(options.vendor.toLowerCase())
            );
        }

        // CVSS minimum
        if (options.cvssMin) {
            results = results.filter(cve => cve.cvss >= options.cvssMin);
        }

        // Sort by CVSS
        results.sort((a, b) => b.cvss - a.cvss);

        return results;
    }

    getCVE(id) {
        return this.cves.find(cve => cve.id.toLowerCase() === id.toLowerCase());
    }

    getStats() {
        const stats = {
            total: this.cves.length,
            bySeverity: {},
            byVendor: {},
            avgCVSS: 0
        };

        let totalCVSS = 0;
        for (const cve of this.cves) {
            stats.bySeverity[cve.severity] = (stats.bySeverity[cve.severity] || 0) + 1;
            stats.byVendor[cve.vendor] = (stats.byVendor[cve.vendor] || 0) + 1;
            totalCVSS += cve.cvss;
        }

        stats.avgCVSS = (totalCVSS / this.cves.length).toFixed(1);

        return stats;
    }

    addCVE(cve) {
        this.cves.push(cve);
        this.save();
    }
}

function printCVE(cve) {
    const severityColors = {
        critical: colors.red,
        high: colors.red,
        medium: colors.yellow,
        low: colors.green
    };
    const color = severityColors[cve.severity] || colors.dim;

    console.log(`\n${colors.bold(cve.id)}`);
    console.log(`  ${color(`[${cve.severity.toUpperCase()}]`)} CVSS: ${cve.cvss}`);
    console.log(`  Vendor: ${cve.vendor}`);
    console.log(`  Product: ${cve.product}`);
    console.log(`  Published: ${cve.published}`);
    console.log(`  ${cve.description}`);
}

function printBanner() {
    console.log(`
${colors.cyan(' __     __    _         ____  ____  ')}
${colors.cyan(' \\ \\   / /   | |       |  _ \\| __ ) ')}
${colors.cyan("  \\ \\ / /   _| |_ __   | | | |  _ \\ ")}
${colors.cyan('   \\ V / |_| | | \'_ \\  | |_| | |_) |')}
${colors.cyan('    \\_/ \\__,_|_|_| |_| |____/|____/ ')}
                              ${colors.dim('v' + VERSION)}
`);
}

function printStats(db) {
    const stats = db.getStats();

    console.log(colors.cyan('─'.repeat(50)));
    console.log(colors.bold('Database Statistics'));
    console.log(colors.cyan('─'.repeat(50)));

    console.log(`\n  Total CVEs: ${stats.total}`);
    console.log(`  Avg CVSS: ${stats.avgCVSS}`);

    console.log('\n  By Severity:');
    for (const [severity, count] of Object.entries(stats.bySeverity)) {
        const bar = '█'.repeat(Math.ceil(count / stats.total * 20));
        console.log(`    ${severity.padEnd(10)} ${bar} ${count}`);
    }

    console.log('\n  By Vendor:');
    const topVendors = Object.entries(stats.byVendor)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);
    for (const [vendor, count] of topVendors) {
        console.log(`    ${vendor.padEnd(20)} ${count}`);
    }
}

function main() {
    const args = process.argv.slice(2);

    if (args.includes('-h') || args.includes('--help')) {
        printBanner();
        console.log(`${colors.bold('Usage:')} vulndb [command] [options]

${colors.bold('Commands:')}
  search <query>    Search CVEs
  get <cve-id>      Get CVE details
  stats             Show database statistics
  list              List all CVEs

${colors.bold('Options:')}
  -s, --severity    Filter by severity
  -v, --vendor      Filter by vendor
  --cvss <min>      Minimum CVSS score
  --demo            Run demo
  -h, --help        Show help
`);
        return;
    }

    printBanner();

    const db = new VulnDB();
    db.load();

    if (args.includes('--demo') || args.length === 0) {
        console.log(colors.yellow('Demo mode - showing sample vulnerabilities\n'));

        printStats(db);

        console.log(`\n${colors.bold('Latest Critical Vulnerabilities:')}`);
        const critical = db.search('', { severity: 'critical' });
        for (const cve of critical.slice(0, 3)) {
            printCVE(cve);
        }
        return;
    }

    const command = args[0];

    if (command === 'search') {
        const query = args[1] || '';
        const options = {};

        const sevIdx = args.findIndex(a => a === '-s' || a === '--severity');
        if (sevIdx >= 0) options.severity = args[sevIdx + 1];

        const vendorIdx = args.findIndex(a => a === '-v' || a === '--vendor');
        if (vendorIdx >= 0) options.vendor = args[vendorIdx + 1];

        const cvssIdx = args.findIndex(a => a === '--cvss');
        if (cvssIdx >= 0) options.cvssMin = parseFloat(args[cvssIdx + 1]);

        const results = db.search(query, options);

        console.log(`Found ${results.length} results for "${query}"\n`);

        for (const cve of results) {
            printCVE(cve);
        }

    } else if (command === 'get') {
        const id = args[1];
        const cve = db.getCVE(id);

        if (cve) {
            printCVE(cve);
            console.log(`\n  References:`);
            for (const ref of cve.references) {
                console.log(`    ${ref}`);
            }
        } else {
            console.log(colors.yellow(`CVE not found: ${id}`));
        }

    } else if (command === 'stats') {
        printStats(db);

    } else if (command === 'list') {
        console.log(`Listing ${db.cves.length} CVEs:\n`);
        for (const cve of db.cves) {
            const color = cve.severity === 'critical' ? colors.red :
                cve.severity === 'high' ? colors.red :
                    cve.severity === 'medium' ? colors.yellow : colors.dim;
            console.log(`${cve.id.padEnd(16)} ${color(cve.severity.padEnd(10))} ${cve.cvss.toFixed(1).padStart(4)} ${cve.description.slice(0, 45)}...`);
        }

    } else {
        console.log(colors.yellow(`Unknown command: ${command}`));
        console.log('Use --help for usage information.');
    }
}

main();
