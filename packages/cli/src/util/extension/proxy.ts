import { createServer } from 'http';
import { Headers } from 'node-fetch';
import {
  toOutgoingHeaders,
  mergeIntoServerResponse,
  buildToHeaders,
} from '@edge-runtime/node-utils';
import type { Server } from 'http';
import type Client from '../client';

const toHeaders = buildToHeaders({ Headers });

export function createProxy(client: Client): Server {
  return createServer(async (req, res) => {
    try {
      // Proxy to the upstream Vercel REST API
      const headers = toHeaders(req.headers);
      headers.delete('host');
      const apiUrl = client.apiUrl || 'http://localhost'; // Use client's configured base URL or fallback to localhost
      const sanitizedUrl = sanitizeUrl(req.url, apiUrl);
      const fetchRes = await client.fetch(sanitizedUrl, {
        headers,
        method: req.method,
        body: req.method === 'GET' || req.method === 'HEAD' ? undefined : req,
        useCurrentTeam: false,
        json: false,
      });
      res.statusCode = fetchRes.status;
      mergeIntoServerResponse(toOutgoingHeaders(fetchRes.headers), res);
      fetchRes.body.pipe(res);
    } catch (err: unknown) {
      client.output.prettyError(err);
      if (!res.headersSent) {
        res.statusCode = 500;
        res.end('Unexpected error during API call');
      }
    }
  });
}
