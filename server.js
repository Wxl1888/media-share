const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const redis = require('redis');
require('dotenv').config();

// 导入模型
const User = require('./models/User');
const Share = require('./models/Share');
const Analytics = require('./models/Analytics');

const app = express();
const PORT = process.env.PORT || 5000;

// ==================== 数据库连接 ====================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/media-share', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ MongoDB 连接成功');
}).catch(err => {
  console.error('❌ MongoDB 连接失败:', err);
});

// ==================== Redis 连接 ====================
let redisClient = null;
if (process.env.REDIS_URL) {
  try {
    redisClient = redis.createClient({
      url: process.env.REDIS_URL
    });
    redisClient.connect().then(() => {
      console.log('✅ Redis 连接成功');
    }).catch(err => {
      console.error('⚠️ Redis 连接失败，继续运行（无缓存）:', err.message);
      redisClient = null;
    });
  } catch (err) {
    console.error('⚠️ Redis 配置错误:', err.message);
  }
}

// ==================== 中间件 ====================
app.use(helmet());
app.use(compression());
app.use(morgan('combined'));
app.use(cors({
  origin: (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(','),
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 速率限制
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: '请求过于频繁，请稍后再试'
});
app.use(limiter);

// ==================== 文件上传配置 ====================
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = `${uuidv4()}${ext}`;
    cb(null, name);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: parseInt(process.env.MAX_FILE_SIZE) || 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedMimes = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'video/mp4',
      'video/webm',
      'video/quicktime'
    ];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('不支持的文件类型'));
    }
  }
});

// ==================== 认证中间件 ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, error: '未提供认证令牌' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, error: '认证令牌无效' });
    }
    req.user = user;
    next();
  });
};

// ==================== 缓存工具函数 ====================
const getCache = async (key) => {
  if (!redisClient) return null;
  try {
    return await redisClient.get(key);
  } catch (err) {
    console.error('缓存读取错误:', err);
    return null;
  }
};

const setCache = async (key, value, ttl = 3600) => {
  if (!redisClient) return;
  try {
    await redisClient.setEx(key, ttl, value);
  } catch (err) {
    console.error('缓存设置错误:', err);
  }
};

// ==================== 分析追踪函数 ====================
const trackEvent = async (userId, shareId, eventType, metadata = {}) => {
  try {
    const analytics = new Analytics({
      userId,
      shareId,
      eventType,
      ipAddress: metadata.ipAddress || 'unknown',
      userAgent: metadata.userAgent || 'unknown',
      metadata: metadata
    });
    await analytics.save();
  } catch (err) {
    console.error('分析记录错误:', err);
  }
};

// ==================== 认证 API ====================

// 注册
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        error: '请提供用户名、邮箱和密码'
      });
    }

    // 检查用户是否已存在
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: '用户名或邮箱已存在'
      });
    }

    // 加密密码
    const hashedPassword = await bcryptjs.hash(password, 10);

    // 创建新用户
    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    // 生成 JWT
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        avatar: user.avatar,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('注册错误:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 登录
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: '请提供邮箱和密码'
      });
    }

    // 查找用户
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        success: false,
        error: '邮箱或密码错误'
      });
    }

    // 验证密码
    const isValidPassword = await bcryptjs.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        error: '邮箱或密码错误'
      });
    }

    // 生成 JWT
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        avatar: user.avatar,
        totalShares: user.totalShares,
        totalViews: user.totalViews
      }
    });
  } catch (error) {
    console.error('登录错误:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 获取当前用户信息
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json({
      success: true,
      user
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 更新用户信息
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { username, bio, avatar } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.user.id,
      {
        username: username || undefined,
        bio: bio || undefined,
        avatar: avatar || undefined,
        updatedAt: new Date()
      },
      { new: true }
    ).select('-password');

    res.json({
      success: true,
      user
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==================== 分享 API ====================

// 创建分享
app.post('/api/shares/create', authenticateToken, upload.array('files', 100), async (req, res) => {
  try {
    const shareId = uuidv4();
    const { title, description, password, expiresIn, isPublic, allowDownload, tags } = req.body;

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        error: '请选择至少一个文件'
      });
    }

    const expiryTime = parseInt(expiresIn) || 7;
    const expiresAt = new Date(Date.now() + expiryTime * 24 * 60 * 60 * 1000);

    const share = new Share({
      shareId,
      userId: req.user.id,
      title: title || '未命名分享',
      description: description || '',
      files: req.files.map(file => ({
        filename: file.filename,
        originalName: file.originalname,
        mimetype: file.mimetype,
        size: file.size,
        uploadedAt: new Date()
      })),
      password: password ? await bcryptjs.hash(password, 5) : null,
      isProtected: !!password,
      expiresAt,
      isPublic: isPublic === 'true',
      allowDownload: allowDownload === 'true',
      tags: tags ? tags.split(',').map(t => t.trim()) : []
    });

    await share.save();

    // 更新用户统计
    await User.findByIdAndUpdate(req.user.id, {
      $inc: { totalShares: 1 }
    });

    // 记录事件
    await trackEvent(
      req.user.id,
      shareId,
      'share',
      { ipAddress: req.ip, userAgent: req.headers['user-agent'] }
    );

    res.status(201).json({
      success: true,
      shareId,
      shareLink: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/share/${shareId}`,
      expiresAt
    });
  } catch (error) {
    console.error('创建分享错误:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// 获取分享信息
app.get('/api/shares/:shareId', async (req, res) => {
  try {
    const { shareId } = req.params;
    const { password } = req.query;

    const cacheKey = `share:${shareId}`;
    let share = JSON.parse(await getCache(cacheKey));

    if (!share) {
      share = await Share.findOne({ shareId });
      if (share) {
        await setCache(cacheKey, JSON.stringify(share), 300);
      }
    }

    if (!share) {
      return res.status(404).json({ success: false, error: '分享不存在或已过期' });
    }

    // 检查密码
    if (share.isProtected) {
      if (!password) {
        return res.status(403).json({ success: false, error: '此分享已受密码保护' });
      }

      const isValidPassword = await bcryptjs.compare(password, share.password);
      if (!isValidPassword) {
        return res.status(403).json({ success: false, error: '密码错误' });
      }
    }

    // 更新访问统计
    share.accessCount += 1;
    share.views += 1;
    share.viewHistory.push({
      ipAddress: req.ip,
      timestamp: new Date(),
      userAgent: req.headers['user-agent']
    });
    await share.save();

    // 清除缓存
    await redisClient?.del(cacheKey).catch(err => console.error('缓存删除错误:', err));

    // 记录浏览事件
    await trackEvent(
      share.userId,
      shareId,
      'view',
      { ipAddress: req.ip, userAgent: req.headers['user-agent'] }
    );

    res.json({
      success: true,
      share: {
        id: share._id,
        shareId: share.shareId,
        title: share.title,
        description: share.description,
        files: share.files.map(f => ({
          filename: f.filename,
          originalName: f.originalName,
          mimetype: f.mimetype,
          size: f.size
        })),
        createdAt: share.createdAt,
        accessCount: share.accessCount,
        isPublic: share.isPublic,
        allowDownload: share.allowDownload,
        tags: share.tags
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 获取用户的分享列表
app.get('/api/shares/user/shares', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const shares = await Share.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Share.countDocuments({ userId: req.user.id });

    res.json({
      success: true,
      shares,
      pagination: {
        total,
        pages: Math.ceil(total / limit),
        currentPage: page
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 删除分享
app.delete('/api/shares/:shareId', authenticateToken, async (req, res) => {
  try {
    const share = await Share.findOneAndDelete({
      shareId: req.params.shareId,
      userId: req.user.id
    });

    if (!share) {
      return res.status(404).json({
        success: false,
        error: '分享不存在或无权限删除'
      });
    }

    // 删除文件
    share.files.forEach(file => {
      const filePath = path.join(uploadsDir, file.filename);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    });

    // 记录删除事件
    await trackEvent(req.user.id, share.shareId, 'delete');

    res.json({ success: true, message: '分享已删除' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 搜索分享
app.get('/api/shares/search/query', async (req, res) => {
  try {
    const { q, tags, page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;

    const query = { isPublic: true };

    if (q) {
      query.$or = [
        { title: { $regex: q, $options: 'i' } },
        { description: { $regex: q, $options: 'i' } }
      ];
    }

    if (tags) {
      query.tags = { $in: tags.split(',') };
    }

    const shares = await Share.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Share.countDocuments(query);

    res.json({
      success: true,
      shares,
      pagination: {
        total,
        pages: Math.ceil(total / limit),
        currentPage: parseInt(page)
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==================== 文件下载 API ====================

// 预览文件
app.get('/api/preview/:shareId/:filename', async (req, res) => {
  try {
    const { shareId, filename } = req.params;
    const { password } = req.query;

    const share = await Share.findOne({ shareId });
    if (!share) {
      return res.status(404).json({ success: false, error: '分享不存在' });
    }

    if (share.isProtected) {
      if (!password) {
        return res.status(403).json({ success: false, error: '需要密码' });
      }

      const isValidPassword = await bcryptjs.compare(password, share.password);
      if (!isValidPassword) {
        return res.status(403).json({ success: false, error: '密码错误' });
      }
    }

    const fileInShare = share.files.find(f => f.filename === filename);
    if (!fileInShare) {
      return res.status(404).json({ success: false, error: '文件不存在' });
    }

    const filePath = path.join(uploadsDir, filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, error: '文件不存在' });
    }

    res.setHeader('Content-Type', fileInShare.mimetype);
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==================== 分析 API ====================

// 获取用户统计
app.get('/api/analytics/stats', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const shares = await Share.find({ userId: req.user.id });
    
    const totalViews = shares.reduce((sum, share) => sum + share.views, 0);
    const totalFiles = shares.reduce((sum, share) => sum + share.files.length, 0);

    res.json({
      success: true,
      stats: {
        totalShares: user.totalShares,
        totalViews,
        totalFiles,
        recentShares: shares.slice(0, 5)
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==================== 健康检查 ====================

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    redis: redisClient ? 'connected' : 'disconnected'
  });
});

// ==================== 错误处理 ====================

app.use((err, req, res, next) => {
  console.error('错误:', err);
  res.status(500).json({
    success: false,
    error: err.message || '服务器内部错误'
  });
});

app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════════════╗
  ║      🚀 媒体分享平台 v2.0 已启动              ║
  ║                                                   ║
  ║  📍 服务器地址: http://localhost:${PORT}         ║
  ║  🗄️  数据库: ${mongoose.connection.readyState === 1 ? '✅ 已连接' : '❌ 未连接'}             ║
  ║  💾 缓存: ${redisClient ? '✅ 已启用' : '⚠️  未启用'}                ║
  ║                                                   ║
  ║  📚 API 文档: http://localhost:${PORT}/api      ║
  ║  💚 健康检查: http://localhost:${PORT}/health   ║
  ╚═══════════════════════════════════════════════════╝
  `);
});

module.exports = app;
