import { createServer } from 'http';
import ejs from 'ejs';
import { readFileSync } from 'fs';
import * as jose from 'jose';
const jwtAlg = 'EdDSA';

const apiEndpoint = process.env.API_ENDPOINT ?? 'http://127.0.0.1:8081';
const index = readFileSync('./index.html', 'utf-8');

const jwk = await jose.importJWK(
    await (
        await fetch(process.env.JWK_ENDPOINT ?? 'http://127.0.0.1:8081')
    ).json(),
    jwtAlg,
);

createServer(async (req, res) => {
    const token = new URL(req.url, 'http://localhost').searchParams.get(
        'token',
    );

    if (!token) {
        return res.end(
            ejs.render(index, {
                query: '',
                result: 'result goes here!',
                endpoint: apiEndpoint,
            }),
        );
    }

    let template;

    try {
        template = (await jose.jwtVerify(token, jwk)).payload?.template;
    } catch (e) {
        return res.end(
            ejs.render(index, {
                query: '',
                result: 'invalid token!',
                endpoint: apiEndpoint,
            }),
        );
    }

    if (!template) {
        return ejs.render(index, {
            query: '',
            result: 'invalid token!',
            endpoint: apiEndpoint,
        })
    }

    try {
        return res.end(
            ejs.render(index, {
                query: template,
                result: ejs.render(template),
                endpoint: apiEndpoint,
            }),
        );
    } catch (e) {
        return res.end(
            ejs.render(index, {
                query: template,
                result: e.toString(),
                endpoint: apiEndpoint,
            }),
        );
    }
}).listen(8080);
