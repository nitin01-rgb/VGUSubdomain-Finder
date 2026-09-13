const domainInput = document.getElementById("domainInput");
const scanButton = document.getElementById("scanButton");

const resultMessage = document.getElementById("resultMessage");
const resultsBody = document.getElementById("resultsBody");

const totalCount = document.getElementById("totalCount");
const liveCount = document.getElementById("liveCount");


/* =========================
   SECURITY HELPER
========================= */

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


/* =========================
   GET DOMAIN
========================= */

function getDomain() {

    const domain = domainInput.value.trim();

    if (!domain) {
        resultMessage.textContent =
            "Please enter a domain first.";

        domainInput.focus();

        return null;
    }

    return domain;
}


/* =========================
   SUBDOMAIN FINDER
========================= */

async function scanSubdomains() {

    const domain = getDomain();

    if (!domain) {
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";
  
    resultMessage.textContent =
        `Searching passive data for ${domain}...`;

    resultsBody.innerHTML = `
        <tr>
            <td colspan="4" class="empty">
                Searching Certificate Transparency data...
            </td>
        </tr>
    `;

    totalCount.textContent = "0";
    liveCount.textContent = "—";


    try {

        const response = await fetch(
            `/api/subdomains?domain=${encodeURIComponent(domain)}`
        );

        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.error || "Scan failed."
            );

        }


        const subdomains =
            data.subdomains || [];


        if (subdomains.length === 0) {

            resultsBody.innerHTML = `
                <tr>
                    <td colspan="4" class="empty">
                        No subdomains found.
                    </td>
                </tr>
            `;

        } else {

            resultsBody.innerHTML = "";

            subdomains.forEach((subdomain) => {

                const row =
                    document.createElement("tr");

                row.innerHTML = `
                    <td>
                        ${escapeHtml(subdomain)}
                    </td>

                    <td>
                        <span style="
                            color:#20a653;
                            font-weight:700;
                        ">
                            Discovered
                        </span>
                    </td>

                    <td>
                        Certificate Transparency record
                    </td>

                    <td>
                        ${escapeHtml(
                            data.source ||
                            "Certificate Transparency"
                        )}
                    </td>
                `;

                resultsBody.appendChild(row);

            });

        }


        totalCount.textContent =
            subdomains.length;

        liveCount.textContent = "—";

        resultMessage.textContent =
            `Found ${subdomains.length} subdomain(s) for ${domain}.`;
             
      saveScanHistory("Subdomain Finder", domain);

    }

    catch (error) {

        resultsBody.innerHTML = `
            <tr>
                <td colspan="4" class="empty">
                    ${escapeHtml(error.message)}
                </td>
            </tr>
        `;

        resultMessage.textContent =
            "Unable to complete the scan.";

    }

    finally {
       
        scanButton.disabled = false;
        scanButton.textContent = "🔍 Scan";

    }

}


/* =========================
   DNS LOOKUP
========================= */

async function lookupDNS() {

    const domain = getDomain();

    if (!domain) {
        return;
    }

    resultMessage.textContent =
        `Looking up DNS records for ${domain}...`;

    resultsBody.innerHTML = `
        <tr>
            <td colspan="4" class="empty">
                Loading DNS records...
            </td>
        </tr>
    `;

    totalCount.textContent = "0";
    liveCount.textContent = "—";


    try {

        const response = await fetch(
            `/api/dns?domain=${encodeURIComponent(domain)}`
        );

        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.error || "DNS lookup failed."
            );

        }


        const records =
            data.records || {};

        let rows = [];
        let count = 0;


        Object.entries(records).forEach(
            ([recordType, values]) => {

                if (!values || values.length === 0) {
                    return;
                }


                values.forEach((value) => {

                    count++;

                    rows.push(`
                        <tr>

                            <td>
                                ${escapeHtml(recordType)}
                            </td>

                            <td>
                                <span style="
                                    color:#20a653;
                                    font-weight:700;
                                ">
                                    Found
                                </span>
                            </td>

                            <td>
                                ${escapeHtml(value)}
                            </td>

                            <td>
                                DNS
                            </td>

                        </tr>
                    `);

                });

            }
        );


        if (rows.length === 0) {

            resultsBody.innerHTML = `
                <tr>
                    <td colspan="4" class="empty">
                        No DNS records found.
                    </td>
                </tr>
            `;

        } else {

            resultsBody.innerHTML =
                rows.join("");

        }


        totalCount.textContent = count;
        liveCount.textContent = "—";

        resultMessage.textContent =
            `Found ${count} DNS record(s) for ${domain}.`;

    }

    catch (error) {

        resultsBody.innerHTML = `
            <tr>
                <td colspan="4" class="empty">
                    ${escapeHtml(error.message)}
                </td>
            </tr>
        `;

        resultMessage.textContent =
            "Unable to complete DNS lookup.";

    }

}


/* =========================
   MAIN SCAN BUTTON
========================= */

scanButton.addEventListener(
    "click",
    scanSubdomains
);


/* =========================
   ENTER KEY
========================= */

domainInput.addEventListener(
    "keydown",
    (event) => {

        if (event.key === "Enter") {
            scanSubdomains();
        }

    }
);


/* =========================
   TOOL BUTTONS
========================= */

const subdomainToolButton =
    document.getElementById(
        "subdomainToolButton"
    );

const dnsButton =
    document.getElementById(
        "dnsButton"
    );


/* =========================
   SUBDOMAIN TOOL
========================= */

if (subdomainToolButton) {

    subdomainToolButton.addEventListener(
        "click",
        () => {

            scanSubdomains();

            document
                .querySelector(".results-section")
                .scrollIntoView({
                    behavior: "smooth"
                });

        }
    );

}


/* =========================
   DNS TOOL
========================= */

if (dnsButton) {

    dnsButton.addEventListener(
        "click",
        () => {

            lookupDNS();

            document
                .querySelector(".results-section")
                .scrollIntoView({
                    behavior: "smooth"
                });

        }
    );

}
/* =========================
   CERTIFICATE LOOKUP
========================= */

const certificateButton =
    document.getElementById("certificateButton");

async function lookupCertificates() {

    const domain = getDomain();

    if (!domain) {
        return;
    }

    resultMessage.textContent =
        `Looking up certificates for ${domain}...`;

    resultsBody.innerHTML = `
        <tr>
            <td colspan="4" class="empty">
                Loading Certificate Transparency records...
            </td>
        </tr>
    `;

    totalCount.textContent = "0";
    liveCount.textContent = "—";


    try {

        const response = await fetch(
            `/api/certificates?domain=${encodeURIComponent(domain)}`
        );

        const data = await response.json();


        if (!response.ok) {
            throw new Error(
                data.error || "Certificate lookup failed."
            );
        }


        const certificates =
            data.certificates || [];

        totalCount.textContent =
            certificates.length;


        if (certificates.length === 0) {

            resultsBody.innerHTML = `
                <tr>
                    <td colspan="4" class="empty">
                        No certificate records found.
                    </td>
                </tr>
            `;

        } else {

            resultsBody.innerHTML = "";

            certificates.forEach((certificate) => {

                const names =
                    Array.isArray(certificate.name)
                        ? certificate.name.join(", ")
                        : certificate.name || "—";

                const row =
                    document.createElement("tr");

                row.innerHTML = `
                    <td>
                        ${escapeHtml(names)}
                    </td>

                    <td>
                        <span style="
                            color:#20a653;
                            font-weight:700;
                        ">
                            Certificate
                        </span>
                    </td>

                    <td>
                        Issuer:
                        ${escapeHtml(
                            certificate.issuer || "—"
                        )}
                        <br>
                        Valid:
                        ${escapeHtml(
                            certificate.not_before || "—"
                        )}
                        →
                        ${escapeHtml(
                            certificate.not_after || "—"
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            data.source ||
                            "Certificate Transparency"
                        )}
                    </td>
                `;

                resultsBody.appendChild(row);

            });

        }


        resultMessage.textContent =
            `Found ${certificates.length} certificate record(s) for ${domain}.`;

    }

    catch (error) {

        resultsBody.innerHTML = `
            <tr>
                <td colspan="4" class="empty">
                    ${escapeHtml(error.message)}
                </td>
            </tr>
        `;

        resultMessage.textContent =
            "Unable to complete certificate lookup.";

    }

}


/* =========================
   CERTIFICATE BUTTON
========================= */

if (certificateButton) {

    certificateButton.addEventListener(
        "click",
        () => {

            lookupCertificates();

            document
                .querySelector(".results-section")
                .scrollIntoView({
                    behavior: "smooth"
                });

        }
    );

}
/* =========================
   HTTP CHECKER
========================= */

const httpButton =
    document.getElementById("httpButton");

async function checkHTTP() {

    const domain = getDomain();

    if (!domain) {
        return;
    }

    resultMessage.textContent =
        `Checking HTTP information for ${domain}...`;

    resultsBody.innerHTML = `
        <tr>
            <td colspan="4" class="empty">
                Checking HTTP response...
            </td>
        </tr>
    `;

    totalCount.textContent = "0";
    liveCount.textContent = "—";


    try {

        const response = await fetch(
            `/api/http-check?domain=${encodeURIComponent(domain)}`
        );

        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.error || "HTTP check failed."
            );

        }


        resultsBody.innerHTML = `

            <tr>
                <td>
                    ${escapeHtml(
                        data.requested_url
                    )}
                </td>

                <td>
                    <span style="
                        color:#20a653;
                        font-weight:700;
                    ">
                        ${escapeHtml(
                            String(data.status_code)
                        )}
                    </span>
                </td>

                <td>
                    Final URL:
                    ${escapeHtml(
                        data.final_url
                    )}
                    <br>
                    Response:
                    ${escapeHtml(
                        String(data.response_time_ms)
                    )} ms
                    <br>
                    Server:
                    ${escapeHtml(
                        data.server || "—"
                    )}
                    <br>
                    Type:
                    ${escapeHtml(
                        data.content_type || "—"
                    )}
                </td>

                <td>
                    HTTP response
                </td>
            </tr>

        `;


        totalCount.textContent = "1";

        liveCount.textContent =
            data.status_code >= 200 &&
            data.status_code < 400
                ? "1"
                : "0";


        resultMessage.textContent =
            `HTTP check completed: ${data.status_code} ${data.status}.`;

    }

    catch (error) {

        resultsBody.innerHTML = `
            <tr>
                <td colspan="4" class="empty">
                    ${escapeHtml(
                        error.message
                    )}
                </td>
            </tr>
        `;

        resultMessage.textContent =
            "Unable to complete HTTP check.";

    }

}


/* =========================
   HTTP BUTTON
========================= */

if (httpButton) {

    httpButton.addEventListener(
        "click",
        () => {

            checkHTTP();

            document
                .querySelector(".results-section")
                .scrollIntoView({
                    behavior: "smooth"
                });

        }
    );

}
/* =========================
   IP / HOST LOOKUP
========================= */

const ipButton =
    document.getElementById("ipButton");

async function lookupIP() {

    const domain = getDomain();

    if (!domain) {
        return;
    }

    resultMessage.textContent =
        `Looking up IP information for ${domain}...`;

    resultsBody.innerHTML = `
        <tr>
            <td colspan="4" class="empty">
                Resolving host IP addresses...
            </td>
        </tr>
    `;

    totalCount.textContent = "0";
    liveCount.textContent = "—";


    try {

        const response = await fetch(
            `/api/ip?domain=${encodeURIComponent(domain)}`
        );

        const data = await response.json();


        if (!response.ok) {
            throw new Error(
                data.error || "IP lookup failed."
            );
        }


        const ips = data.ips || [];


        if (ips.length === 0) {

            resultsBody.innerHTML = `
                <tr>
                    <td colspan="4" class="empty">
                        No IP addresses found.
                    </td>
                </tr>
            `;

        } else {

            resultsBody.innerHTML = "";

            ips.forEach((ip) => {

                const row =
                    document.createElement("tr");

                row.innerHTML = `
                    <td>
                        ${escapeHtml(ip)}
                    </td>

                    <td>
                        <span style="
                            color:#20a653;
                            font-weight:700;
                        ">
                            Resolved
                        </span>
                    </td>

                    <td>
                        Host:
                        ${escapeHtml(domain)}
                    </td>

                    <td>
                        ${escapeHtml(
                            data.source ||
                            "DNS / Host Resolution"
                        )}
                    </td>
                `;

                resultsBody.appendChild(row);

            });

        }


        totalCount.textContent = ips.length;
        liveCount.textContent = "—";

        resultMessage.textContent =
            `Found ${ips.length} IP address(es) for ${domain}.`;

    }

    catch (error) {

        resultsBody.innerHTML = `
            <tr>
                <td colspan="4" class="empty">
                    ${escapeHtml(error.message)}
                </td>
            </tr>
        `;

        resultMessage.textContent =
            "Unable to complete IP lookup.";

    }

}


/* =========================
   IP BUTTON
========================= */

if (ipButton) {

    ipButton.addEventListener(
        "click",
        () => {

            lookupIP();

            document
                .querySelector(".results-section")
                .scrollIntoView({
                    behavior: "smooth"
                });

        }
    );

}
// =========================
// WHOIS / RDAP LOOKUP
// =========================

async function lookupWHOIS() {

    const domain = getDomain();

    if (!domain) {
        resultMessage.textContent = "Please enter a domain.";
        return;
    }

    resultMessage.textContent = "Fetching WHOIS / RDAP information...";

    try {

        const response = await fetch(
            `/api/whois?domain=${encodeURIComponent(domain)}`
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error || "WHOIS lookup failed"
            );
        }

        resultsBody.innerHTML = "";

        const rows = [
            ["Domain", data.domain || "—"],
            ["Registered", data.registered || "—"],
            ["Expiration", data.expiration || "—"],
            ["Last Changed", data.last_changed || "—"],
            [
                "Nameservers",
                (data.nameservers || []).join(", ") || "—"
            ],
            [
                "Status",
                (data.status || []).join(", ") || "—"
            ],
            ["Source", data.source || "RDAP"]
        ];

        rows.forEach(([key, value]) => {

            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${escapeHtml(key)}</td>
                <td>${escapeHtml(value)}</td>
            `;

            resultsBody.appendChild(row);
        });

        totalCount.textContent = "1";
        liveCount.textContent = "1";

        resultMessage.textContent =
            `WHOIS information found for ${data.domain}`;

    } catch (error) {

        resultMessage.textContent =
            error.message || "WHOIS lookup failed";

        resultsBody.innerHTML = "";
        totalCount.textContent = "0";
        liveCount.textContent = "0";
    }
}


// =========================
// WHOIS BUTTON
// =========================

if (whoisButton) {
    whoisButton.addEventListener(
        "click",
        lookupWHOIS
    );
}
// =========================
// URL / DOMAIN PARSER
// =========================

async function parseURL() {

    const input = prompt(
        "Enter a URL or domain:",
        domainInput.value.trim()
    );

    if (!input) {
        return;
    }

    resultMessage.textContent =
        "Parsing URL...";

    try {

        const response = await fetch(
            `/api/parser?url=${encodeURIComponent(input)}`
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error || "URL parsing failed"
            );
        }

        resultsBody.innerHTML = "";

        const rows = [
            ["Original URL", data.original_url || "—"],
            ["Protocol", data.protocol || "—"],
            ["Hostname", data.hostname || "—"],
            ["Port", data.port || "—"],
            ["Path", data.path || "—"],
            ["Query", data.query || "—"],
            ["Fragment", data.fragment || "—"],
            ["Username", data.username || "—"],
            ["Source", data.source || "URL Parser"]
        ];

        rows.forEach(([key, value]) => {

            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${escapeHtml(String(key))}</td>
                <td>${escapeHtml(String(value))}</td>
            `;

            resultsBody.appendChild(row);
        });

        totalCount.textContent = "1";
        liveCount.textContent = "1";

        resultMessage.textContent =
            "URL parsed successfully.";

    } catch (error) {

        resultMessage.textContent =
            error.message || "URL parsing failed";

        resultsBody.innerHTML = "";
        totalCount.textContent = "0";
        liveCount.textContent = "0";
    }
}


// =========================
// PARSER BUTTON
// =========================

if (parserButton) {
    parserButton.addEventListener(
        "click",
        parseURL
    );
}
// =========================
// TECHNOLOGY DETECTION
// =========================

async function detectTechnology() {

    const domain = getDomain();

    if (!domain) {
        resultMessage.textContent =
            "Please enter a domain.";
        return;
    }

    resultMessage.textContent =
        "Detecting technologies...";

    try {

        const response = await fetch(
            `/api/tech?domain=${encodeURIComponent(domain)}`
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error || "Technology detection failed"
            );
        }

        resultsBody.innerHTML = "";

        if (
            !data.technologies ||
            data.technologies.length === 0
        ) {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>Technology</td>
                <td>No visible technology information found</td>
            `;

            resultsBody.appendChild(row);

        } else {

            data.technologies.forEach(item => {

                const row = document.createElement("tr");

                row.innerHTML = `
                    <td>${escapeHtml(
                        String(item.technology || "—")
                    )}</td>
                    <td>${escapeHtml(
                        String(item.value || "—")
                    )}</td>
                `;

                resultsBody.appendChild(row);
            });
        }

        totalCount.textContent =
            String(data.technologies?.length || 0);

        liveCount.textContent = "1";

        resultMessage.textContent =
            `Technology detection completed for ${data.domain}.`;

    } catch (error) {

        resultMessage.textContent =
            error.message ||
            "Technology detection failed";

        resultsBody.innerHTML = "";
        totalCount.textContent = "0";
        liveCount.textContent = "0";
    }
}


// =========================
// TECHNOLOGY BUTTON
// =========================

if (techButton) {
    techButton.addEventListener(
        "click",
        detectTechnology
    );
}
// =========================
// CSV / JSON EXPORT
// =========================

function getCurrentResults() {

    const rows = [];

    document.querySelectorAll("#resultsBody tr").forEach(row => {

        const cells = row.querySelectorAll("td");

        if (cells.length >= 2) {

            rows.push({
                field: cells[0].innerText.trim(),
                value: cells[1].innerText.trim()
            });
        }
    });

    return rows;
}


function downloadFile(content, filename, type) {

    const blob = new Blob(
        [content],
        { type: type }
    );

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;
    link.download = filename;

    document.body.appendChild(link);

    link.click();

    link.remove();

    URL.revokeObjectURL(url);
}


// =========================
// JSON EXPORT
// =========================

function exportJSON() {

    const data = getCurrentResults();

    if (data.length === 0) {

        alert(
            "No results available to export."
        );

        return;
    }

    const output = {
        domain: getDomain(),
        exported_at: new Date().toISOString(),
        results: data
    };

    downloadFile(
        JSON.stringify(output, null, 2),
        "vgu-subdomain-results.json",
        "application/json"
    );
}


// =========================
// CSV EXPORT
// =========================

function exportCSV() {

    const data = getCurrentResults();

    if (data.length === 0) {

        alert(
            "No results available to export."
        );

        return;
    }

    const lines = [
        "Field,Value"
    ];

    data.forEach(item => {

        const field = `"${item.field.replace(/"/g, '""')}"`;

        const value = `"${item.value.replace(/"/g, '""')}"`;

        lines.push(
            `${field},${value}`
        );
    });

    downloadFile(
        lines.join("\n"),
        "vgu-subdomain-results.csv",
        "text/csv"
    );
}


// =========================
// EXPORT BUTTON
// =========================

if (exportButton) {

    exportButton.addEventListener(
        "click",
        function () {

            const format = prompt(
                "Enter export format: CSV or JSON",
                "JSON"
            );

            if (!format) {
                return;
            }

            if (
                format.toLowerCase() === "csv"
            ) {
                exportCSV();

            } else if (
                format.toLowerCase() === "json"
            ) {
                exportJSON();

            } else {

                alert(
                    "Please enter CSV or JSON."
                );
            }
        }
    );
}
// =========================
// SCAN HISTORY
// =========================

function saveScanHistory(tool, domain) {

    if (!domain) {
        return;
    }

    const history =
        JSON.parse(
            localStorage.getItem("vguScanHistory") || "[]"
        );

    history.unshift({
        tool: tool,
        domain: domain,
        time: new Date().toLocaleString()
    });

    // Keep latest 20 entries
    const limitedHistory =
        history.slice(0, 20);

    localStorage.setItem(
        "vguScanHistory",
        JSON.stringify(limitedHistory)
    );
}


function showScanHistory() {

    const history =
        JSON.parse(
            localStorage.getItem("vguScanHistory") || "[]"
        );

    resultsBody.innerHTML = "";

    if (history.length === 0) {

        const row = document.createElement("tr");

        row.innerHTML = `
            <td>History</td>
            <td>No scan history available</td>
        `;

        resultsBody.appendChild(row);

        resultMessage.textContent =
            "No scan history available.";

        totalCount.textContent = "0";
        liveCount.textContent = "0";

        return;
    }

    history.forEach(item => {

        const row = document.createElement("tr");

        row.innerHTML = `
            <td>${escapeHtml(item.tool)}</td>
            <td>
                ${escapeHtml(item.domain)}
                <br>
                <small>${escapeHtml(item.time)}</small>
            </td>
        `;

        resultsBody.appendChild(row);
    });

    totalCount.textContent =
        String(history.length);

    liveCount.textContent = "1";

    resultMessage.textContent =
        `Showing ${history.length} recent history entries.`;
}


// =========================
// HISTORY BUTTON
// =========================

if (historyButton) {

    historyButton.addEventListener(
        "click",
        showScanHistory
    );
}
