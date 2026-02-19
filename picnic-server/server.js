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

// Recursively find all products/articles in the Picnic search response
function extractProducts(obj, products = []) {
  if (!obj) return products;

  // If this object has an id and name, it's likely a product
  if (obj.id && obj.name && typeof obj.name === 'string') {
    // Skip category/group headers (they usually don't have prices)
    const hasPrice = obj.display_price != null || obj.price != null || obj.unit_quantity;
    if (hasPrice) {
      products.push({
        id: obj.id,
        name: obj.name,
        price: obj.display_price != null ? obj.display_price : (obj.price || 0),
        unit: obj.unit_quantity || obj.unit_quantity_sub || '',
        image: obj.image_id ? `https://storefront-prod.nl.picnicinternational.com/static/images/${obj.image_id}/small.png` : null
      });
    }
  }

  // Recurse into arrays and objects
  if (Array.isArray(obj)) {
    for (const item of obj) {
      extractProducts(item, products);
    }
  } else if (typeof obj === 'object') {
    for (const key of Object.keys(obj)) {
      if (typeof obj[key] === 'object' && obj[key] !== null) {
        extractProducts(obj[key], products);
      }
    }
  }

  return products;
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

    // Log raw response structure for debugging (first search only)
    if (!app._searchLogged) {
      console.log('Raw search response for "' + q + '":', JSON.stringify(results).substring(0, 2000));
      app._searchLogged = true;
    }

    // Recursively extract all products from the response
    const products = extractProducts(results);

    // Deduplicate by id
    const seen = new Set();
    const unique = products.filter(p => {
      if (seen.has(p.id)) return false;
      seen.add(p.id);
      return true;
    });

    res.json({ products: unique });
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
