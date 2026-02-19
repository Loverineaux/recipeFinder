const express = require('express');
const cors = require('cors');
const PicnicClient = require('picnic-api');

const app = express();
app.use(cors());
app.use(express.json());

// Store authenticated clients per session (in-memory)
const sessions = new Map();

// Cleanup old sessions every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, session] of sessions) {
    if (now - session.lastUsed > 60 * 60 * 1000) { // 1 hour
      sessions.delete(key);
    }
  }
}, 30 * 60 * 1000);

// Simple session key from auth
function getSessionKey(username) {
  return Buffer.from(username).toString('base64');
}

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'picnic-bridge' });
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'username en password zijn verplicht' });
    }

    const client = new PicnicClient({ countryCode: 'NL' });
    await client.login(username, password);

    const sessionKey = getSessionKey(username);
    sessions.set(sessionKey, {
      client,
      username,
      lastUsed: Date.now()
    });

    res.json({ success: true, sessionKey });
  } catch (err) {
    console.error('Login failed:', err.message);
    res.status(401).json({ error: 'Login mislukt. Controleer je gegevens.' });
  }
});

// Middleware to get authenticated client
function getClient(req, res) {
  const sessionKey = req.headers['x-session-key'];
  if (!sessionKey) {
    res.status(401).json({ error: 'Niet ingelogd. Log eerst in.' });
    return null;
  }
  const session = sessions.get(sessionKey);
  if (!session) {
    res.status(401).json({ error: 'Sessie verlopen. Log opnieuw in.' });
    return null;
  }
  session.lastUsed = Date.now();
  return session.client;
}

// Search products
app.get('/api/search', async (req, res) => {
  const client = getClient(req, res);
  if (!client) return;

  try {
    const { q } = req.query;
    if (!q) {
      return res.status(400).json({ error: 'Zoekterm (q) is verplicht' });
    }

    const results = await client.search(q);

    // Flatten results into a simple product list
    const products = [];
    if (Array.isArray(results)) {
      for (const group of results) {
        const items = group.items || [];
        for (const item of items) {
          if (item.type === 'SINGLE_ARTICLE' || item.type === 'PRODUCT') {
            products.push({
              id: item.id,
              name: item.name,
              price: item.display_price != null ? item.display_price : (item.price || 0),
              unit: item.unit_quantity || '',
              image: item.image_id ? `https://storefront-prod.nl.picnicinternational.com/static/images/${item.image_id}/small.png` : null
            });
          }
        }
      }
    }

    res.json({ products });
  } catch (err) {
    console.error('Search failed:', err.message);
    res.status(500).json({ error: 'Zoeken mislukt: ' + err.message });
  }
});

// Add product to cart
app.post('/api/cart/add', async (req, res) => {
  const client = getClient(req, res);
  if (!client) return;

  try {
    const { productId, quantity } = req.body;
    if (!productId) {
      return res.status(400).json({ error: 'productId is verplicht' });
    }

    await client.addProductToShoppingCart(productId, quantity || 1);
    res.json({ success: true });
  } catch (err) {
    console.error('Add to cart failed:', err.message);
    res.status(500).json({ error: 'Toevoegen aan winkelwagen mislukt: ' + err.message });
  }
});

// Get cart
app.get('/api/cart', async (req, res) => {
  const client = getClient(req, res);
  if (!client) return;

  try {
    const cart = await client.getShoppingCart();
    res.json({ cart });
  } catch (err) {
    console.error('Get cart failed:', err.message);
    res.status(500).json({ error: 'Winkelwagen ophalen mislukt: ' + err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Picnic bridge server running on port ${PORT}`);
});
