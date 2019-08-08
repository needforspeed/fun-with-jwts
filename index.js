const express = require('express')
const jwt = require('njwt')
const session = require('express-session')
const { ExpressOIDC } = require('@okta/oidc-middleware')

require('dotenv').config()

const app = express()
const port = process.env.PORT || 3000

app.use(session({
  secret: process.env.APP_SECRET,
  resave: true,
  saveUninitialized: false
}))

const cfg = {
  appBaseUrl: `${process.env.HOST_URL}`,
  issuer: `${process.env.OKTA_ORG_URL}/oauth2/default`,
  client_id: process.env.OKTA_CLIENT_ID,
  client_secret: process.env.OKTA_CLIENT_SECRET,
  redirect_uri: `${process.env.HOST_URL}/implicit/callback`,
  scope: 'openid profile'
}

const oidc = new ExpressOIDC(cfg)

app.use(oidc.router)

app.get('/create', (req, res) => {
  if (req.headers.authorization !== 'Basic QXp1cmVEaWFtb25kOmh1bnRlcjI=') {
    res.set('WWW-Authenticate', 'Basic realm="401"')
    res.status(401).send('Try user: AzureDiamond, password: hunter2')
    return
  }

  const claims = { iss: 'fun-with-jwts', sub: 'AzureDiamond' }
  const token = jwt.create(claims, 'top-secret-phrase')

  token.setExpiration(new Date().getTime() + 60*1000)
  res.send(token.compact())
})

app.get('/verify/:token', (req, res) => {
  const { token } = req.params
  jwt.verify(token, 'top-secret-phrase', (err, verifiedJwt) => {
    if(err) {
      res.send(err.message)
    } else {
      res.send(verifiedJwt)
    }
  })
})

app.get('/', oidc.ensureAuthenticated(), (req, res) => res.send('Peekaboo'))

app.listen(port, () => console.log(`JWT server listening on port ${port}!`))

