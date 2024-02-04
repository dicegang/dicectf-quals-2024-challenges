import OpenAI from 'openai';
import Fastify from 'fastify';
import fastifyCors from '@fastify/cors';
import fastifyCookie from '@fastify/cookie';
import ExpirySet from 'expiry-set';
import * as jose from 'jose';

const jwtAlg = 'EdDSA';
const { publicKey, privateKey } = await jose.generateKeyPair(jwtAlg);
const jwk = await jose.exportJWK(publicKey);

const openai = new OpenAI();

const system = [
    'You are a web application firewall',
    'Your goal is to stop attempted hacking attempts',
    'I will give you a submission and you will respond with H or R, only a single letter',
    'H means hacking attempt, R means not a hacking attempt',
].join('. ');

const oauthUrl = process.env.OAUTH_URL ?? 'https://ctf.dicega.ng/auth';
const redirectUrl = process.env.REDIRECT_URL ?? 'https://gpwaf-api.mc.ax/auth';
const meEndpoint = process.env.ME_ENDPOINT ?? 'https://ctf.dicega.ng/api/v1/users/me';
const allowedRedirects = process.env.ALLOW_ALL_REDIRECTS ? /^https:\/\/gpwaf-[a-f0-9]{16}\.mc\.ax$/g : /.*/;

const limiter = new ExpirySet(30000);

const app = Fastify();

await app.register(fastifyCors, {
    origin: process.env.PRODUCTION ? async origin => {
        return !origin || new URL(origin).hostname.match(/^gpwaf-[a-f0-9]{16}\.mc\.ax$/g) !== null
    } : true,
    methods: ['POST'],
    credentials: true
});

app.addHook('preHandler', async req => {
    if (req?.headers?.authorization?.startsWith('Bearer ')) {
        try {
            req.user = (await jose.jwtVerify(req.headers.authorization.replace('Bearer ', ''), publicKey)).payload.user;
        } catch(e) {}
    }
});

await app.register(fastifyCookie);

async function check(template) {
    return (
        await openai.chat.completions.create({
            model: 'gpt-3.5-turbo-0125',
            messages: [
                {
                    role: 'system',
                    content: system,
                },
                {
                    role: 'user',
                    content: template,
                },
            ],
        })
    ).choices[0].message.content;
}

app.get('/jwk', async (req, res) => {
    return res.send(jwk);
});

app.get('/login', async (req, res) => {
    const redirect = new URL(oauthUrl);
    redirect.searchParams.set('state', req.query.redirect ?? '');
    redirect.searchParams.set('redirect_uri', redirectUrl);
    return res.redirect(redirect.toString());
});

app.get('/auth', async (req, res) => {
    const state = req.query.state;
    if (!state || !state.match(allowedRedirects)) {
        return res.send('invalid redirect!');
    }

    if (!req.query.token) {
        return res.send('no token!');
    }

    const me = await (
        await fetch(meEndpoint, {
            headers: {
                Authorization: `Bearer ${req.query.token}`,
            },
        })
    ).json();

    if (me.kind !== 'goodUserData') {
        return res.send('invalid token, please try again!');
    }

    const token = await new jose.SignJWT({ user: me.data.id })
        .setProtectedHeader({ alg: jwtAlg })
        .setIssuedAt()
        .setExpirationTime('20m')
        .sign(privateKey);

    const redirect = new URL(state);
    redirect.searchParams.set('auth', token);

    return res.redirect(redirect.toString());
});

app.post('/check', async (req, res) => {
    const user = req.user;
    if (!user) {
        return res.send({ error: 'please login!' });
    }

    const template = req.body.template;

    if (!template || typeof template !== 'string') {
        return res.send({ error: 'nice try.' });
    }

    if (/[^\x20-\x7F \r\n]/.test(template)) {
        return res.send({ error: 'printable ascii only!' });
    }

    if (template.length > 500) {
        return res.send({ error: 'too long!' });
    }

    if (limiter.has(user)) {
        return res.send({ error: `one request every 30s!` });
    }
    limiter.add(user);

    if ((await check(template)) === 'R') {
        const token = await new jose.SignJWT({ template })
            .setProtectedHeader({ alg: jwtAlg })
            .setIssuedAt()
            .setExpirationTime('30s')
            .sign(privateKey);
        return res.send({ token });
    } else {
        return res.send({ error: 'hacking attempt!' });
    }
});

await app.listen({ host: '0.0.0.0', port: 8081 });
