const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'fame8-super-secret-key-2024';
const TEMP_DIR = path.join(__dirname, 'temp');
const VIDEO_EXPIRY_HOURS = 2;

// Google OAuth Config - Set these in Render Environment Variables
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://fame8-frontend.vercel.app';

// Hugging Face API Config
const HUGGINGFACE_API_KEY = process.env.HUGGINGFACE_API_KEY;

// Ensure temp directory exists
if (!fs.existsSync(TEMP_DIR)) {
  fs.mkdirSync(TEMP_DIR, { recursive: true });
}

// Initialize SQLite database
const db = new Database(path.join(__dirname, 'fame8.db'));

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS brands (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    niche TEXT,
    tone TEXT DEFAULT 'professional',
    target_audience TEXT,
    colors TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS social_accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    brand_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    account_name TEXT,
    access_token TEXT,
    connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (brand_id) REFERENCES brands(id)
  );

  CREATE TABLE IF NOT EXISTS videos (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    brand_id TEXT NOT NULL,
    title TEXT NOT NULL,
    script TEXT,
    topic TEXT,
    status TEXT DEFAULT 'pending',
    temp_path TEXT,
    recipe TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (brand_id) REFERENCES brands(id)
  );

  CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY,
    video_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    post_url TEXT,
    status TEXT DEFAULT 'pending',
    posted_at DATETIME,
    FOREIGN KEY (video_id) REFERENCES videos(id)
  );

  CREATE TABLE IF NOT EXISTS topics (
    id TEXT PRIMARY KEY,
    brand_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    trending_score REAL DEFAULT 0,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (brand_id) REFERENCES brands(id)
  );
`);

// Middleware
app.use(cors());
app.use(express.json());
app.use('/temp', express.static(TEMP_DIR));

// Auth middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// ============== AUTH ROUTES ==============

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    db.prepare('INSERT INTO users (id, email, password, name) VALUES (?, ?, ?, ?)')
      .run(userId, email, hashedPassword, name);

    const token = jwt.sign({ id: userId, email, name }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user: { id: userId, email, name } });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT id, email, name, created_at FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

// ============== GOOGLE OAUTH ROUTES ==============

// Redirect to Google
app.get('/api/auth/google', (req, res) => {
  const redirectUri = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${GOOGLE_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent('https://fame8-backend-1.onrender.com/api/auth/google/callback')}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('email profile')}` +
    `&access_type=offline`;
  res.redirect(redirectUri);
});

// Google callback
app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    
    if (!code) {
      return res.redirect(`${FRONTEND_URL}?error=no_code`);
    }

    // Exchange code for tokens
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: 'https://fame8-backend-1.onrender.com/api/auth/google/callback',
        grant_type: 'authorization_code'
      })
    });

    const tokens = await tokenResponse.json();
    
    if (!tokens.access_token) {
      console.error('Token error:', tokens);
      return res.redirect(`${FRONTEND_URL}?error=token_failed`);
    }

    // Get user info from Google
    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });

    const googleUser = await userInfoResponse.json();
    
    if (!googleUser.email) {
      return res.redirect(`${FRONTEND_URL}?error=no_email`);
    }

    // Check if user exists
    let user = db.prepare('SELECT * FROM users WHERE email = ?').get(googleUser.email);
    
    if (!user) {
      // Create new user
      const userId = uuidv4();
      const randomPassword = uuidv4(); // Google users don't need password
      const hashedPassword = await bcrypt.hash(randomPassword, 10);
      
      db.prepare('INSERT INTO users (id, email, password, name) VALUES (?, ?, ?, ?)')
        .run(userId, googleUser.email, hashedPassword, googleUser.name || googleUser.email.split('@')[0]);
      
      user = { id: userId, email: googleUser.email, name: googleUser.name || googleUser.email.split('@')[0] };
    }

    // Create JWT token
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });

    // Redirect to frontend with token
    res.redirect(`${FRONTEND_URL}?token=${token}`);
  } catch (error) {
    console.error('Google OAuth error:', error);
    res.redirect(`${FRONTEND_URL}?error=oauth_failed`);
  }
});

// ============== BRAND ROUTES ==============

app.get('/api/brands', authenticate, (req, res) => {
  const brands = db.prepare('SELECT * FROM brands WHERE user_id = ?').all(req.user.id);
  res.json(brands);
});

app.post('/api/brands', authenticate, (req, res) => {
  const { name, niche, tone, target_audience, colors } = req.body;
  const brandId = uuidv4();

  db.prepare(`
    INSERT INTO brands (id, user_id, name, niche, tone, target_audience, colors)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(brandId, req.user.id, name, niche, tone, target_audience, JSON.stringify(colors || {}));

  // Generate initial topics for the brand
  generateTopicsForBrand(brandId, niche);

  const brand = db.prepare('SELECT * FROM brands WHERE id = ?').get(brandId);
  res.json(brand);
});

app.put('/api/brands/:id', authenticate, (req, res) => {
  const { name, niche, tone, target_audience, colors } = req.body;
  
  db.prepare(`
    UPDATE brands SET name = ?, niche = ?, tone = ?, target_audience = ?, colors = ?
    WHERE id = ? AND user_id = ?
  `).run(name, niche, tone, target_audience, JSON.stringify(colors || {}), req.params.id, req.user.id);

  const brand = db.prepare('SELECT * FROM brands WHERE id = ?').get(req.params.id);
  res.json(brand);
});

app.delete('/api/brands/:id', authenticate, (req, res) => {
  db.prepare('DELETE FROM brands WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ success: true });
});

// ============== SOCIAL ACCOUNTS ROUTES ==============

app.get('/api/brands/:brandId/social-accounts', authenticate, (req, res) => {
  const accounts = db.prepare('SELECT * FROM social_accounts WHERE brand_id = ? AND user_id = ?')
    .all(req.params.brandId, req.user.id);
  res.json(accounts);
});

app.post('/api/brands/:brandId/social-accounts', authenticate, (req, res) => {
  const { platform, account_name, access_token } = req.body;
  const accountId = uuidv4();

  // Check if account already exists for this platform
  const existing = db.prepare('SELECT id FROM social_accounts WHERE brand_id = ? AND platform = ?')
    .get(req.params.brandId, platform);
  
  if (existing) {
    db.prepare('UPDATE social_accounts SET account_name = ?, access_token = ? WHERE id = ?')
      .run(account_name, access_token, existing.id);
    const account = db.prepare('SELECT * FROM social_accounts WHERE id = ?').get(existing.id);
    return res.json(account);
  }

  db.prepare(`
    INSERT INTO social_accounts (id, user_id, brand_id, platform, account_name, access_token)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(accountId, req.user.id, req.params.brandId, platform, account_name, access_token);

  const account = db.prepare('SELECT * FROM social_accounts WHERE id = ?').get(accountId);
  res.json(account);
});

app.delete('/api/social-accounts/:id', authenticate, (req, res) => {
  db.prepare('DELETE FROM social_accounts WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ success: true });
});

// ============== TOPICS ROUTES ==============

app.get('/api/brands/:brandId/topics', authenticate, (req, res) => {
  const topics = db.prepare('SELECT * FROM topics WHERE brand_id = ? ORDER BY trending_score DESC')
    .all(req.params.brandId);
  res.json(topics);
});

app.post('/api/brands/:brandId/topics/generate', authenticate, (req, res) => {
  const brand = db.prepare('SELECT * FROM brands WHERE id = ? AND user_id = ?')
    .get(req.params.brandId, req.user.id);
  
  if (!brand) {
    return res.status(404).json({ error: 'Brand not found' });
  }

  generateTopicsForBrand(req.params.brandId, brand.niche);
  
  const topics = db.prepare('SELECT * FROM topics WHERE brand_id = ? ORDER BY trending_score DESC')
    .all(req.params.brandId);
  res.json(topics);
});

// ============== VIDEO ROUTES ==============

app.get('/api/videos', authenticate, (req, res) => {
  const videos = db.prepare(`
    SELECT v.*, b.name as brand_name 
    FROM videos v 
    JOIN brands b ON v.brand_id = b.id 
    WHERE v.user_id = ? 
    ORDER BY v.created_at DESC
  `).all(req.user.id);
  res.json(videos);
});

app.get('/api/brands/:brandId/videos', authenticate, (req, res) => {
  const videos = db.prepare('SELECT * FROM videos WHERE brand_id = ? AND user_id = ? ORDER BY created_at DESC')
    .all(req.params.brandId, req.user.id);
  res.json(videos);
});

app.post('/api/videos/generate', authenticate, async (req, res) => {
  try {
    const { brand_id, topic, custom_script } = req.body;

    const brand = db.prepare('SELECT * FROM brands WHERE id = ? AND user_id = ?')
      .get(brand_id, req.user.id);
    
    if (!brand) {
      return res.status(404).json({ error: 'Brand not found' });
    }

    const videoId = uuidv4();
    const script = custom_script || generateScript(topic, brand);
    const expiresAt = new Date(Date.now() + VIDEO_EXPIRY_HOURS * 60 * 60 * 1000).toISOString();

    // Create video record
    db.prepare(`
      INSERT INTO videos (id, user_id, brand_id, title, script, topic, status, expires_at, recipe)
      VALUES (?, ?, ?, ?, ?, ?, 'generating', ?, ?)
    `).run(videoId, req.user.id, brand_id, topic, script, topic, expiresAt, JSON.stringify({
      topic,
      script,
      brand: brand.name,
      tone: brand.tone,
      niche: brand.niche
    }));

    // Simulate video generation (in production, this would call FFmpeg/video APIs)
    setTimeout(() => {
      generateMockVideo(videoId);
    }, 3000);

    res.json({ 
      video_id: videoId, 
      status: 'generating',
      message: 'Video generation started. Check status endpoint for updates.'
    });
  } catch (error) {
    console.error('Video generation error:', error);
    res.status(500).json({ error: 'Failed to generate video' });
  }
});

app.get('/api/videos/:id', authenticate, (req, res) => {
  const video = db.prepare(`
    SELECT v.*, b.name as brand_name 
    FROM videos v 
    JOIN brands b ON v.brand_id = b.id 
    WHERE v.id = ? AND v.user_id = ?
  `).get(req.params.id, req.user.id);
  
  if (!video) {
    return res.status(404).json({ error: 'Video not found' });
  }

  res.json(video);
});

app.get('/api/videos/:id/status', authenticate, (req, res) => {
  const video = db.prepare('SELECT id, status, temp_path, expires_at FROM videos WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  
  if (!video) {
    return res.status(404).json({ error: 'Video not found' });
  }

  const timeRemaining = video.expires_at ? 
    Math.max(0, new Date(video.expires_at) - new Date()) : 0;

  res.json({
    ...video,
    time_remaining_ms: timeRemaining,
    download_url: video.status === 'ready' ? `/temp/${path.basename(video.temp_path || '')}` : null
  });
});

app.get('/api/videos/:id/download', authenticate, (req, res) => {
  const video = db.prepare('SELECT * FROM videos WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  
  if (!video || !video.temp_path) {
    return res.status(404).json({ error: 'Video not found or not ready' });
  }

  if (!fs.existsSync(video.temp_path)) {
    return res.status(410).json({ error: 'Video has expired' });
  }

  res.download(video.temp_path, `${video.title.replace(/[^a-z0-9]/gi, '_')}.mp4`);
});

app.post('/api/videos/:id/post', authenticate, async (req, res) => {
  try {
    const { platforms } = req.body;
    const video = db.prepare('SELECT * FROM videos WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.id);
    
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const results = [];
    
    for (const platform of platforms) {
      const postId = uuidv4();
      
      // In production, this would call the actual social media APIs
      db.prepare(`
        INSERT INTO posts (id, video_id, platform, status, posted_at)
        VALUES (?, ?, ?, 'posted', CURRENT_TIMESTAMP)
      `).run(postId, video.id, platform);

      results.push({
        platform,
        status: 'posted',
        post_id: postId
      });
    }

    // Update video status
    db.prepare("UPDATE videos SET status = 'posted' WHERE id = ?").run(video.id);

    // Clean up temp file after posting
    if (video.temp_path && fs.existsSync(video.temp_path)) {
      fs.unlinkSync(video.temp_path);
    }

    res.json({ success: true, results });
  } catch (error) {
    console.error('Post error:', error);
    res.status(500).json({ error: 'Failed to post video' });
  }
});

app.delete('/api/videos/:id', authenticate, (req, res) => {
  const video = db.prepare('SELECT temp_path FROM videos WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.id);
  
  if (video && video.temp_path && fs.existsSync(video.temp_path)) {
    fs.unlinkSync(video.temp_path);
  }

  db.prepare('DELETE FROM posts WHERE video_id = ?').run(req.params.id);
  db.prepare('DELETE FROM videos WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  
  res.json({ success: true });
});

// ============== POSTS ROUTES ==============

app.get('/api/videos/:videoId/posts', authenticate, (req, res) => {
  const posts = db.prepare('SELECT * FROM posts WHERE video_id = ?').all(req.params.videoId);
  res.json(posts);
});

app.get('/api/posts', authenticate, (req, res) => {
  const posts = db.prepare(`
    SELECT p.*, v.title as video_title, b.name as brand_name
    FROM posts p
    JOIN videos v ON p.video_id = v.id
    JOIN brands b ON v.brand_id = b.id
    WHERE v.user_id = ?
    ORDER BY p.posted_at DESC
  `).all(req.user.id);
  res.json(posts);
});

// ============== DASHBOARD STATS ==============

app.get('/api/stats', authenticate, (req, res) => {
  const totalVideos = db.prepare('SELECT COUNT(*) as count FROM videos WHERE user_id = ?')
    .get(req.user.id).count;
  const totalPosts = db.prepare(`
    SELECT COUNT(*) as count FROM posts p
    JOIN videos v ON p.video_id = v.id
    WHERE v.user_id = ?
  `).get(req.user.id).count;
  const totalBrands = db.prepare('SELECT COUNT(*) as count FROM brands WHERE user_id = ?')
    .get(req.user.id).count;
  const connectedAccounts = db.prepare('SELECT COUNT(*) as count FROM social_accounts WHERE user_id = ?')
    .get(req.user.id).count;

  res.json({
    total_videos: totalVideos,
    total_posts: totalPosts,
    total_brands: totalBrands,
    connected_accounts: connectedAccounts
  });
});

// ============== HELPER FUNCTIONS ==============

function generateTopicsForBrand(brandId, niche) {
  const topicTemplates = {
    'technology': [
      '5 AI Tools That Will Change Your Workflow',
      'The Future of Remote Work Technology',
      'Top Productivity Apps for 2024',
      'How Automation Is Transforming Business',
      'Cybersecurity Tips Every Professional Needs'
    ],
    'fitness': [
      '10-Minute Morning Workout Routine',
      'Nutrition Myths Debunked',
      'Best Recovery Techniques for Athletes',
      'Home Gym Essentials on a Budget',
      'Mental Health Benefits of Exercise'
    ],
    'finance': [
      'Investment Strategies for Beginners',
      'Budgeting Tips That Actually Work',
      'Understanding Cryptocurrency Basics',
      'Building Multiple Income Streams',
      'Retirement Planning in Your 20s'
    ],
    'marketing': [
      'Social Media Trends to Watch',
      'Content Marketing Strategies That Convert',
      'Email Marketing Best Practices',
      'Building Your Personal Brand',
      'SEO Tips for Small Businesses'
    ],
    'default': [
      'Industry Trends You Need to Know',
      'Tips for Professional Growth',
      'Common Mistakes to Avoid',
      'Success Stories and Lessons',
      'Future Predictions for Your Field'
    ]
  };

  const topics = topicTemplates[niche?.toLowerCase()] || topicTemplates['default'];
  
  topics.forEach((title, index) => {
    const topicId = uuidv4();
    const trendingScore = Math.random() * 100;
    
    db.prepare(`
      INSERT INTO topics (id, brand_id, title, trending_score)
      VALUES (?, ?, ?, ?)
    `).run(topicId, brandId, title, trendingScore);
  });
}

function generateScript(topic, brand) {
  const toneStyles = {
    'professional': {
      intro: `Welcome! Today we're diving into ${topic}.`,
      style: 'informative and authoritative'
    },
    'casual': {
      intro: `Hey there! Let's talk about ${topic}.`,
      style: 'friendly and conversational'
    },
    'energetic': {
      intro: `What's up everyone! Get ready to learn about ${topic}!`,
      style: 'exciting and dynamic'
    },
    'educational': {
      intro: `In this video, we'll explore ${topic} in detail.`,
      style: 'clear and instructive'
    }
  };

  const style = toneStyles[brand.tone] || toneStyles['professional'];

  return `
${style.intro}

[Scene 1: Introduction]
Hook your audience with a compelling question or statement about ${topic}.

[Scene 2: Main Content]
Present the key points about ${topic} in a ${style.style} manner.
- Point 1: Explain the first key concept
- Point 2: Share relevant examples or data
- Point 3: Provide actionable insights

[Scene 3: Conclusion]
Summarize the main takeaways and include a call-to-action.

Don't forget to follow ${brand.name} for more content like this!

#${brand.niche || 'content'} #${topic.replace(/\s+/g, '')} #${brand.name.replace(/\s+/g, '')}
  `.trim();
}

// Generate video using Hugging Face API
async function generateHuggingFaceVideo(videoId) {
  const video = db.prepare('SELECT * FROM videos WHERE id = ?').get(videoId);
  if (!video) return;

  const tempPath = path.join(TEMP_DIR, `${videoId}.mp4`);

  try {
    console.log(`Starting video generation for: ${video.topic}`);
    
    // Update status to generating
    db.prepare("UPDATE videos SET status = 'generating' WHERE id = ?").run(videoId);

    // Use Hugging Face's text-to-video model (Ali-Vilab/text-to-video-ms-1.7b)
    const response = await fetch(
      "https://api-inference.huggingface.co/models/ali-vilab/text-to-video-ms-1.7b",
      {
        headers: {
          Authorization: `Bearer ${HUGGINGFACE_API_KEY}`,
          "Content-Type": "application/json",
        },
        method: "POST",
        body: JSON.stringify({
          inputs: video.topic,
          parameters: {
            num_frames: 16,
            num_inference_steps: 25
          }
        }),
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Hugging Face API error:', response.status, errorText);
      
      // If model is loading, retry after delay
      if (response.status === 503) {
        console.log('Model is loading, retrying in 30 seconds...');
        setTimeout(() => generateHuggingFaceVideo(videoId), 30000);
        return;
      }
      
      // Fallback to placeholder if API fails
      console.log('Falling back to placeholder video');
      await generatePlaceholderVideo(videoId, video.topic);
      return;
    }

    // Get the video blob
    const videoBuffer = await response.arrayBuffer();
    fs.writeFileSync(tempPath, Buffer.from(videoBuffer));

    console.log(`Video generated successfully: ${tempPath}`);
    
    db.prepare("UPDATE videos SET status = 'ready', temp_path = ? WHERE id = ?")
      .run(tempPath, videoId);

  } catch (error) {
    console.error('Video generation error:', error);
    
    // Fallback to placeholder
    await generatePlaceholderVideo(videoId, video.topic);
  }
}

// Fallback: Generate a simple placeholder video using a public sample
async function generatePlaceholderVideo(videoId, topic) {
  const tempPath = path.join(TEMP_DIR, `${videoId}.mp4`);
  
  try {
    // Download a sample video from a public source as placeholder
    const sampleVideoUrl = 'https://www.w3schools.com/html/mov_bbb.mp4';
    const response = await fetch(sampleVideoUrl);
    
    if (response.ok) {
      const videoBuffer = await response.arrayBuffer();
      fs.writeFileSync(tempPath, Buffer.from(videoBuffer));
      
      db.prepare("UPDATE videos SET status = 'ready', temp_path = ? WHERE id = ?")
        .run(tempPath, videoId);
      
      console.log(`Placeholder video created for: ${topic}`);
    } else {
      throw new Error('Failed to download placeholder video');
    }
  } catch (error) {
    console.error('Placeholder video error:', error);
    db.prepare("UPDATE videos SET status = 'failed' WHERE id = ?").run(videoId);
  }
}

// Legacy function - kept for compatibility
function generateMockVideo(videoId) {
  generateHuggingFaceVideo(videoId);
}

// Cleanup expired videos every hour
cron.schedule('0 * * * *', () => {
  console.log('Running cleanup job...');
  const expiredVideos = db.prepare(`
    SELECT id, temp_path FROM videos 
    WHERE expires_at < CURRENT_TIMESTAMP AND temp_path IS NOT NULL
  `).all();

  expiredVideos.forEach(video => {
    if (video.temp_path && fs.existsSync(video.temp_path)) {
      fs.unlinkSync(video.temp_path);
      console.log(`Cleaned up: ${video.temp_path}`);
    }
    db.prepare("UPDATE videos SET temp_path = NULL, status = 'expired' WHERE id = ?").run(video.id);
  });
});

// Cleanup temp directory on startup
function cleanupTempDirectory() {
  if (fs.existsSync(TEMP_DIR)) {
    const files = fs.readdirSync(TEMP_DIR);
    files.forEach(file => {
      const filePath = path.join(TEMP_DIR, file);
      const stats = fs.statSync(filePath);
      const hoursSinceModified = (Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60);
      if (hoursSinceModified > VIDEO_EXPIRY_HOURS) {
        fs.unlinkSync(filePath);
        console.log(`Startup cleanup: ${filePath}`);
      }
    });
  }
}

cleanupTempDirectory();

// Start server
app.listen(PORT, () => {
  console.log(`Fame8 API server running on port ${PORT}`);
  console.log(`Temp directory: ${TEMP_DIR}`);
});

module.exports = app;
