import * as dns from "dns";
import * as net from "net";
import * as tls from "tls";
import * as crypto from "crypto";
import {DKIMSign} from "./dkim";
import * as fs from "node:fs/promises";

function dkimSigned(rfc822message: string, dkimOptions: DKIMOptions) {
    const dkimSignature = DKIMSign(rfc822message, {
        domainName: dkimOptions.domain,
        keySelector: dkimOptions.keySelector,
        privateKey: dkimOptions.privateKey,
    });

    return dkimSignature + '\r\n' + rfc822message
}

export interface DKIMOptions {
    domain: string;
    keySelector: string | 'default'
    privateKey: string
}

export interface SendEnvelope {
    from: string
    to: string | string[];     // Allow multiple recipients
    cc?: string | string[];     // Optional CC recipients
    bcc?: string | string[];    // Optional BCC recipients
    subject: string
    body: string;       // Plain text body
    html?: string;      // Optional HTML body
    attachments?: Array<EnvelopeAttachment>;
}

export interface EnvelopeAttachment {
    filename: string;
    path: string; // File path
    contentType: string;
}

const DEFAULT_PORT = 25;
const DEFAULT_CONNECT_TIMEOUT = 30000;
const DEFAULT_READ_TIMEOUT = 60000;
const DEFAULT_MX_LOOKUP_TIMEOUT = 10000;

export interface PostmanOptions {
    dkim?: DKIMOptions
    // Mail server port, default 25
    port?: number
    logger?: Console

    readTimeout?: number;       // Time in milliseconds for read timeout
    connectionTimeout?: number; // Time in milliseconds for connection timeout
    mxLookupTimeout?: number;   // Time in milliseconds for MX lookup timeout
}

function formatAddresses(addresses: string | string[]): string {
    if (Array.isArray(addresses)) {
        return addresses.join(', ');
    }
    return addresses;
}

// Function to generate a unique Message-ID
function generateMessageId(domain: string) {
    const uniquePart = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    return `<${uniquePart}.${timestamp}@${domain}>`;
}

async function getMailExchange(domain: string, timeout: number): Promise<string> {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error(`DNS resolution timed out after ${timeout}ms`));
        }, timeout);

        dns.resolveMx(domain, (err, addresses) => {
            clearTimeout(timer); // Clear the timeout when we get a response

            if (err) {
                return reject(new Error(`Failed to resolve MX records for domain ${domain}: ${err.message}`));
            }

            if (!addresses || addresses.length === 0) {
                return reject(new Error(`No MX records found for domain ${domain}`));
            }

            // Sort MX records by priority and return the exchange with the highest priority
            const mxRecord = addresses.sort((a, b) => a.priority - b.priority)[0];

            resolve(mxRecord.exchange);
        });
    });
}


async function encodeAttachment(attachment: EnvelopeAttachment, boundary: string): Promise<string> {
    // Read the file content as a binary buffer
    const fileContent = await fs.readFile(attachment.path);

    // Convert the binary buffer to a Base64-encoded string
    const base64Content = fileContent.toString('base64');

    // Format the attachment part with the necessary MIME headers
    return `
--${boundary}
Content-Type: ${attachment.contentType}; name="${attachment.filename}"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="${attachment.filename}"

${base64Content}
`;
}


async function createEmailMessage(sendOptions: SendEnvelope, dkim: undefined | DKIMOptions): Promise<string> {
    const {from, to, cc, bcc, subject, body, attachments, html} = sendOptions;
    const fromDomain = from.split('@')[1];

    // Generate boundaries for mixed and alternative parts
    const mixedBoundary = '--boundary_' + crypto.randomBytes(16).toString('hex');
    const alternativeBoundary = '--boundary_' + crypto.randomBytes(16).toString('hex');

    let message = `Message-ID: ${generateMessageId(fromDomain)}\r\n`;
    message += `From: ${from}\r\n`;
    message += `To: ${formatAddresses(to)}\r\n`;

    if (cc) {
        message += `CC: ${formatAddresses(cc)}\r\n`;
    }

    if (bcc) {
        message += `BCC: ${formatAddresses(bcc)}\r\n`;
    }

    message += `Subject: ${subject}\r\n`;
    message += `MIME-Version: 1.0\r\n`;
    message += `Content-Type: multipart/mixed; boundary="${mixedBoundary}"\r\n\r\n`;

    // Add the multipart/alternative part for text/plain and text/html
    message += `--${mixedBoundary}\r\n`;
    message += `Content-Type: multipart/alternative; boundary="${alternativeBoundary}"\r\n\r\n`;

    // Add plain text part
    message += `--${alternativeBoundary}\r\n`;
    message += `Content-Type: text/plain; charset="utf-8"\r\n\r\n`;
    message += `${body}\r\n`;

    // Add HTML part if provided
    if (html) {
        message += `--${alternativeBoundary}\r\n`;
        message += `Content-Type: text/html; charset="utf-8"\r\n\r\n`;
        message += `${html}\r\n`;
    }

    // Close the alternative boundary
    message += `--${alternativeBoundary}--\r\n`;

    // Add attachments if any
    if (attachments) {
        for (let attachment of attachments) {
            message += await encodeAttachment(attachment, mixedBoundary);
        }
    }

    // Close the mixed boundary
    message += `--${mixedBoundary}--\r\n`;


    if (dkim) {
        return dkimSigned(message, dkim)
    } else {
        return message
    }
}

export interface RecipientGroup {
    mxHost: string;
    recipients: string[];
}

async function getRecipientsByMx(sendOptions: SendEnvelope, timeout: number): Promise<RecipientGroup[]> {
    const allRecipients = [] as string[];

    // Combine to, cc, and bcc into a single list of recipients
    if (Array.isArray(sendOptions.to)) {
        allRecipients.push(...sendOptions.to);
    } else {
        allRecipients.push(sendOptions.to);
    }

    if (Array.isArray(sendOptions.cc)) {
        allRecipients.push(...sendOptions.cc);
    } else if (sendOptions.cc) {
        allRecipients.push(sendOptions.cc);
    }

    if (Array.isArray(sendOptions.bcc)) {
        allRecipients.push(...sendOptions.bcc);
    } else if (sendOptions.bcc) {
        allRecipients.push(sendOptions.bcc);
    }

    // Map of domain to recipients
    const domainMap: { [domain: string]: string[] } = {};

    // Group recipients by their domain
    allRecipients.forEach(recipient => {
        const domain = recipient.split('@')[1];
        if (!domainMap[domain]) {
            domainMap[domain] = [];
        }
        domainMap[domain].push(recipient);
    });

    // Perform MX lookup for each unique domain
    return await Promise.all(
        Object.keys(domainMap).map(async domain => {
            const mxHost = await getMailExchange(domain, timeout);
            return {
                mxHost,
                recipients: domainMap[domain]
            };
        })
    );
}

export default class Postman {
    constructor(private readonly options: PostmanOptions) {
    }

    async send(sendOptions: SendEnvelope): Promise<string> {
        const logger = this.options.logger;

        // Group recipients by their MX host
        const recipientGroups = await getRecipientsByMx(sendOptions, this.options.mxLookupTimeout ?? DEFAULT_MX_LOOKUP_TIMEOUT);

        for (const group of recipientGroups) {
            const { mxHost, recipients } = group;

            try {
                await new Promise((resolve, reject) => {
                    const client = net.createConnection(this.options.port ?? DEFAULT_PORT, mxHost, () => {
                        if (logger) logger.log(`Connected to exchange server ${mxHost}`);
                    });

                    client.on('timeout', () => {
                        client.destroy();
                        return reject(new Error('Operation timed out'));
                    });

                    // Set connection timeout
                    client.setTimeout(this.options.connectionTimeout ?? DEFAULT_CONNECT_TIMEOUT);
                    client.once('data', () => {
                        client.setTimeout(0); // Disable the timeout after receiving data
                    });

                    let greeted = false;

                    client.on('data', (data) => {
                        if (logger) logger.log('Response from server:', data.toString());

                        const serverData = data.toString();
                        const code = parseInt(serverData.substring(0, 3));

                        if (code === 220 && !greeted) {
                            client.write(`EHLO ${mxHost}\r\n`);
                        } else if (code === 250 && !greeted) {
                            greeted = true;

                            if (serverData.includes('250-STARTTLS')) {
                                client.write('STARTTLS\r\n');
                            } else {
                                client.destroy();
                                return reject(new Error('Must accept TLS'));
                            }
                        } else if (code === 220 && serverData.includes('TLS') && greeted) {
                            // Upgrade to TLS
                            const tlsSocket = tls.connect({
                                socket: client,
                                servername: mxHost,
                                timeout: this.options.connectionTimeout ?? DEFAULT_CONNECT_TIMEOUT
                            }, () => {
                                if (logger) logger.log('TLS connection established');
                                tlsSocket.write(`EHLO ${mxHost}\r\n`);
                            });

                            let tlsGreeted = false;

                            // Handle the SMTP conversation over TLS
                            tlsSocket.on('data', (tlsData) => {
                                const tlsResponse = tlsData.toString();
                                const code = parseInt(tlsResponse.substring(0, 3));

                                if (logger) logger.log('TLS Server:', tlsResponse);

                                if (code === 250 && !tlsGreeted) {
                                    tlsSocket.write(`MAIL FROM:<${sendOptions.from}>\r\n`);

                                    recipients.forEach(recipient => {
                                        tlsSocket.write(`RCPT TO:<${recipient}>\r\n`);
                                    });

                                    tlsSocket.write('DATA\r\n');

                                    tlsGreeted = true;
                                } else if (code === 354) {
                                    createEmailMessage(sendOptions, this.options.dkim).then(message => {
                                        tlsSocket.write(message);
                                        tlsSocket.write('.\r\n'); // End of data
                                    }).catch(reject);
                                } else if (code === 250 && tlsResponse.includes('2.0.0')) {
                                    tlsSocket.write('QUIT\r\n');
                                    resolve('Email sent successfully');
                                    tlsSocket.end();
                                } else if (code >= 500) {
                                    tlsSocket.destroy();
                                    return reject(new Error(`TLS error: ${tlsResponse}`));
                                }
                            });

                            tlsSocket.on('error', (err) => {
                                tlsSocket.destroy();
                                return reject(new Error(`TLS error: ${err.message}`));
                            });

                            tlsSocket.on('end', () => {
                                if (logger) logger.log('TLS connection closed');
                            });
                        } else if (code >= 500) {
                            client.destroy();
                            return reject(new Error(`SMTP error: ${serverData}`));
                        }
                    });

                    client.on('error', (err) => {
                        client.destroy();
                        return reject(new Error(`SMTP error: ${err.message}`));
                    });

                    client.on('end', () => {
                        if (logger) logger.log('Connection closed');
                    });
                });
            } catch (error) {
                return Promise.reject(error); // Immediately reject if any group fails
            }
        }

        return 'Email sent successfully';
    }
}