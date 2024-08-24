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
    to: string
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

export interface PostmanOptions {
    dkim?: DKIMOptions
    // Mail server port, default 25
    port?: number
    logger?: Console
}

// Function to generate a unique Message-ID
function generateMessageId(domain: string) {
    const uniquePart = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    return `<${uniquePart}.${timestamp}@${domain}>`;
}

async function getMailExchange(domain: string): Promise<string> {
    return new Promise((resolve, reject) => {
        dns.resolveMx(domain, (err, addresses) => {
            if (err) {
                return reject(err);
            }

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
    const {from, to, subject, body, attachments, html} = sendOptions;
    const fromDomain = from.split('@')[1];

    // Generate boundaries for mixed and alternative parts
    const mixedBoundary = '--boundary_' + crypto.randomBytes(16).toString('hex');
    const alternativeBoundary = '--boundary_' + crypto.randomBytes(16).toString('hex');

    let message = `Message-ID: ${generateMessageId(fromDomain)}\r\n`;
    message += `From: ${from}\r\n`;
    message += `To: ${to}\r\n`;
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

export default class Postman {
    constructor(private readonly options: PostmanOptions) {
    }

    async send(sendOptions: SendEnvelope) {
        const {to, from} = sendOptions;
        const logger = this.options.logger

        const toDomain = to.split('@')[1];

        const mxHost = await getMailExchange(toDomain);

        return new Promise((resolve, reject) => {
            const client = net.createConnection(this.options.port ?? 25, mxHost, () => {
                if (logger)
                    logger.log('Connected to exchange server')
            })

            let greeted = false;

            client.on('data', (data) => {
                if (logger)
                    logger.log('Response from server:', data.toString());

                let serverData = data.toString();
                const code = parseInt(serverData.substring(0, 3))

                if (code === 220 && !greeted) {
                    client.write(`EHLO ${mxHost}\r\n`);
                } else if (code === 250 && !greeted) {
                    greeted = true;

                    if (serverData.includes('250-STARTTLS')) {
                        client.write('STARTTLS\r\n');
                    } else {
                        reject('Must accept TLS');
                    }
                } else if (code === 220 && serverData.includes('TLS') && greeted) {
                    // Upgrade to TLS
                    const tlsSocket = tls.connect({
                        socket: client,
                        servername: mxHost
                    }, () => {
                        if (logger)
                            logger.log('TLS connection established');

                        tlsSocket.write(`EHLO ${mxHost}\r\n`);
                    });

                    let tlsGreeted = false;

                    // Handle the SMTP conversation over TLS
                    tlsSocket.on('data', (data) => {
                        const tlsResponse = data.toString();
                        const code = parseInt(tlsResponse.substring(0, 3))

                        if (logger)
                            logger.log('TLS Server:', tlsResponse);

                        if (code === 250 && !tlsGreeted) {
                            tlsSocket.write(`MAIL FROM:<${from}>\r\n`);
                            tlsSocket.write(`RCPT TO:<${to}>\r\n`);
                            tlsSocket.write('DATA\r\n');

                            tlsGreeted = true;
                        } else if (code === 354) {
                            createEmailMessage(sendOptions, this.options.dkim).then(message => {
                                tlsSocket.write(message);
                                // important
                                tlsSocket.write('.\r\n');
                            }).catch(reject);
                        } else if (code === 250 && tlsResponse.includes('2.0.0')) {
                            tlsSocket.write('QUIT\r\n');
                            resolve('Email sent successfully');

                            tlsSocket.end()
                        } else if (code >= 500) {
                            reject(`TLS error: ${tlsResponse}`);

                            tlsSocket.end()
                        }
                    });

                    tlsSocket.on('error', (err) => {
                        reject(`TLS error: ${err.message}`);
                    });

                    tlsSocket.on('end', () => {
                        if (logger)
                            logger.log('TLS connection closed');
                    });
                } else if (code >= 500) {
                    reject(`SMTP error: ${serverData}`);

                    client.end()
                }
            });

            client.on('error', (err) => {
                reject(`SMTP error: ${err.message}`);
            });

            client.on('end', () => {
                if (logger)
                    logger.log('Connection closed');
            });
        });
    }
}