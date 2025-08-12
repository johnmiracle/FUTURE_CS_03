import http from "http";
import { fileURLToPath } from "url";
import { dirname, join, extname } from "path";
import { createReadStream, createWriteStream } from "fs";
import { stat, mkdir, readFile, writeFile, access } from "fs/promises";
import crypto from "crypto";
import Busboy from "busboy";
import { v4 as uuidv4 } from "uuid";

const __filename = fileURLToPath(import.meta.url);  
const __dirname = dirname(__filename);

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = join(__dirname, "public");
const STORAGE_DIR = join(__dirname, "storage");
const DATA_FILE = join(STORAGE_DIR, "index.json");

// ---- Security / upload policy ----
const MAX_SIZE = 25 * 1024 * 1024; // 25MB per file
const ALLOWED_EXT = new Set([".pdf", ".png", ".jpg", ".jpeg", ".txt", ".doc", ".docx", ".xlsx", ".zip", ".csv"]);

// AES-256-GCM key: from ENV or derived from passphrase
const PASSPHRASE = process.env.SECRET_PASSPHRASE || "change-this-in-prod";
const KEY = crypto.scryptSync(PASSPHRASE, "file-share-salt", 32); // 32 bytes

// ---- Utils ----
const sendJSON = (res, code, data, headers = {}) => {
    const body = JSON.stringify(data);
    res.writeHead(code, {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": Buffer.byteLength(body),
        ...headers,
    });
    res.end(body);
};


const notFound = (res) => sendJSON(res, 404, { error: "Not Found" });
const badRequest = (res, msg) => sendJSON(res, 400, { error: msg });

// minimal static server
const tryServeStatic = (req, res) => {
    if (req.method !== "GET") return false;
    const url = new URL(req.url, `http://${req.headers.host}`);
    let filepath = url.pathname === "/" ? "/index.html" : url.pathname;
    if (filepath.includes("..")) return false;

    const full = join(PUBLIC_DIR, filepath);
    stat(full).then(info => {
        if (!info.isFile()) return notFound(res);
        // set a couple of content-types
        const ext = extname(full).toLowerCase();
        const map = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css" };
        res.writeHead(200, { "Content-Type": map[ext] || "application/octet-stream" });
        createReadStream(full).pipe(res);
    }).catch(() => notFound(res));
    return true;
};

const withCORS = (req, res) => {
    const headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    };
    if (req.method === "OPTIONS") {
        res.writeHead(204, headers); res.end(); return true;
    }
    res._corsHeaders = headers; return false;
};

// storage helpers
async function ensureStorage() {
    try { await access(STORAGE_DIR); } catch { await mkdir(STORAGE_DIR, { recursive: true }); }
    try { await access(DATA_FILE); } catch { await writeFile(DATA_FILE, "[]"); }
}

async function loadIndex() {
    const raw = await readFile(DATA_FILE, "utf8");
    return JSON.parse(raw);
}

async function saveIndex(rows) {
    await writeFile(DATA_FILE, JSON.stringify(rows, null, 2));
}

// encryption helpers
function encryptToFile(srcStream, outPath) {
    const iv = crypto.randomBytes(12); // GCM recommended 96-bit IV
    const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);
    const out = createWriteStream(outPath);
    let size = 0;

    return new Promise((resolve, reject) => {
        srcStream.on("data", (chunk) => (size += chunk.length));
        srcStream.pipe(cipher).pipe(out);
        out.on("finish", () => {
            const authTag = cipher.getAuthTag();
            resolve({ iv: iv.toString("hex"), tag: authTag.toString("hex"), size });
        });
        out.on("error", reject);
        cipher.on("error", reject);
        srcStream.on("error", reject);
    });
}

function decryptToStream(inPath, ivHex, tagHex) {
    const iv = Buffer.from(ivHex, "hex");
    const tag = Buffer.from(tagHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-gcm", KEY, iv);
    decipher.setAuthTag(tag);
    return createReadStream(inPath).pipe(decipher);
}

// upload (multipart/form-data) -> encrypt -> store
async function handleUpload(req, res) {
    if (req.method !== "POST") return badRequest(res, "Invalid method");
    const bb = Busboy({ headers: req.headers, limits: { fileSize: MAX_SIZE, files: 1 } });

    let fileHandled = false;
    let meta = { originalName: null, mime: null };

    bb.on("file", (fieldname, file, info) => {
        const { filename, mimeType } = info;
        const ext = extname(filename || "").toLowerCase();
        meta.originalName = filename || "upload.bin";
        meta.mime = mimeType || "application/octet-stream";

        if (!ALLOWED_EXT.has(ext)) {
            file.resume();
            bb.emit("error", new Error(`Extension not allowed: ${ext || "unknown"}`));
            return;
        }

        const id = uuidv4();
        const encPath = join(STORAGE_DIR, `${id}.enc`);

        fileHandled = true;
        encryptToFile(file, encPath)
            .then(async ({ iv, tag, size }) => {
                const rows = await loadIndex();
                rows.unshift({
                    id,
                    original_name: meta.originalName,
                    mime: meta.mime,
                    size_bytes: size,
                    created_at: new Date().toISOString(),
                    iv,
                    tag,
                    path: encPath
                });
                await saveIndex(rows);
                sendJSON(res, 201, { id, name: meta.originalName, size }, res._corsHeaders);
            })
            .catch((err) => {
                console.error(err);
                sendJSON(res, 500, { error: err.message || "Encryption failed" }, res._corsHeaders);
            });
    });

    bb.on("field", () => { }); // ignore extra fields for now

    bb.on("error", (err) => {
        if (!res.writableEnded) sendJSON(res, 400, { error: err.message }, res._corsHeaders);
    });

    bb.on("finish", () => {
        if (!fileHandled && !res.writableEnded) {
            sendJSON(res, 400, { error: "No file received" }, res._corsHeaders);
        }
    });

    req.pipe(bb);
}

// list files (metadata only)
async function handleList(_req, res) {
    const rows = await loadIndex();
    // Hide iv/tag/path in the public list
    const out = rows.map(({ id, original_name, size_bytes, created_at }) => ({
        id, original_name, size_bytes, created_at
    }));
    sendJSON(res, 200, out, res._corsHeaders);
}

// download -> decrypt stream
async function handleDownload(req, res, id) {
    const rows = await loadIndex();
    const row = rows.find((r) => r.id === id);
    if (!row) return notFound(res);

    res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": `attachment; filename="${row.original_name.replace(/"/g, '')}"`,
        ...res._corsHeaders
    });

    decryptToStream(row.path, row.iv, row.tag)
        .on("error", (e) => {
            console.error(e);
            if (!res.headersSent) res.writeHead(500, { "Content-Type": "text/plain" });
            res.end("Decryption failed");
        })
        .pipe(res);
}

// ---- Server (routes) ----
await ensureStorage();

const server = http.createServer(async (req, res) => {
    if (withCORS(req, res)) return;

    const url = new URL(req.url, `http://${req.headers.host}`);
    const { pathname } = url;

    try {
        // API routes
        if (req.method === "POST" && pathname === "/upload") {
            return handleUpload(req, res);
        }

        if (req.method === "GET" && pathname === "/files") {
            return handleList(req, res);
        }

        if (req.method === "GET" && pathname.startsWith("/download/")) {
            const id = pathname.split("/").pop();
            if (!id) return badRequest(res, "Missing id");
            return handleDownload(req, res, id);
        }

        // Optional: health/status
        if (req.method === "GET" && pathname === "/health") {
            return sendJSON(res, 200, { status: "ok", uptime: process.uptime() }, res._corsHeaders);
        }

        // static
        if (pathname === "/" || pathname.endsWith(".html") || pathname.startsWith("/assets/") || pathname.startsWith("/scripts/") || pathname.startsWith("/styles/")) {
            return tryServeStatic(req, res);
        }

        return notFound(res);
    } catch (err) {
        console.error(err);
        return sendJSON(res, 500, { error: err?.message || "Server error" }, res._corsHeaders);
    }
});

// graceful shutdown
const shutdown = () => {
    console.log("\nShutting down...");
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

server.listen(PORT, () => {
    console.log(`▶ Server running at http://localhost:${PORT}`);
    console.log(`   Upload limit: ${Math.round(MAX_SIZE / 1024 / 1024)}MB`);
});
