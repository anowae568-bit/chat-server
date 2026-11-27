import 'dotenv/config';
import crypto from 'node:crypto';
import http from 'node:http';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { Server } from 'socket.io';

// =============================================================================
// 1. CONFIGURATION & ENVIRONMENT
// =============================================================================

const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const MONGODB_URI = process.env.MONGODB_URI || '';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// Never hardcode a fallback secret literal; generate an ephemeral key if unset
// so dev boots work while warning operators to set JWT_SECRET on Render.
const JWT_SECRET =
  process.env.JWT_SECRET && process.env.JWT_SECRET.trim().length >= 16
    ? process.env.JWT_SECRET.trim()
    : (() => {
        console.warn(
          '[WARN] JWT_SECRET is missing or shorter than 16 chars. Using an ephemeral key; set JWT_SECRET on Render so sessions survive restarts.'
        );
        return crypto.randomBytes(32).toString('hex');
      })();

const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME?.trim() || '';
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY?.trim() || '';
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET?.trim() || '';

if (CLOUDINARY_CLOUD_NAME && CLOUDINARY_API_KEY && CLOUDINARY_API_SECRET) {
  cloudinary.config({
    cloud_name: CLOUDINARY_CLOUD_NAME,
    api_key: CLOUDINARY_API_KEY,
    api_secret: CLOUDINARY_API_SECRET,
    secure: true,
  });
}

function isCloudinaryConfigured() {
  return Boolean(CLOUDINARY_CLOUD_NAME && CLOUDINARY_API_KEY && CLOUDINARY_API_SECRET);
}

const allowedOrigins = new Set(
  [
    ...(process.env.CORS_ORIGIN || '').split(','),
    process.env.RENDER_EXTERNAL_URL || '',
    process.env.APP_URL || '',
  ]
    .map((o) => o.trim())
    .filter(Boolean)
);

function corsOriginCheck(origin, callback) {
  // Allow non-browser / same-origin requests without an Origin header
  if (!origin) return callback(null, true);
  if (allowedOrigins.has(origin)) return callback(null, true);
  if (
    NODE_ENV !== 'production' &&
    /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)
  ) {
    return callback(null, true);
  }
  return callback(new Error('Origin not allowed by CORS'));
}

// =============================================================================
// 2. MONGOOSE SCHEMAS & MODELS (MongoDB Atlas — Zero Local Disk Storage)
// =============================================================================

const { Schema, Types } = mongoose;

const UserSchema = new Schema(
  {
    username: { type: String, required: true, trim: true, maxlength: 30 },
    usernameLower: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    displayName: { type: String, required: true, trim: true, maxlength: 60 },
    passwordHash: { type: String, required: true, select: false },
    avatarUrl: { type: String, default: '', trim: true },
    bio: { type: String, default: '', trim: true, maxlength: 240 },
    followersCount: { type: Number, default: 0, min: 0 },
    followingCount: { type: Number, default: 0, min: 0 },
    isOnline: { type: Boolean, default: false },
    lastSeenAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const GroupMemberSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    role: { type: String, enum: ['leader', 'member'], default: 'member' },
    joinedAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const GroupSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 80 },
    nameLower: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    description: { type: String, default: '', trim: true, maxlength: 400 },
    photoUrl: { type: String, default: '', trim: true },
    leader: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    members: { type: [GroupMemberSchema], default: [] },
    followersCount: { type: Number, default: 0, min: 0 },
    inviteCode: { type: String, index: true, sparse: true },
    inviteExpiresAt: { type: Date },
    inviteCreatedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true }
);
GroupSchema.index({ 'members.user': 1 });

const ReadReceiptSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    readAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const MessageSchema = new Schema(
  {
    chatType: { type: String, enum: ['dm', 'group'], required: true },
    conversationKey: { type: String, required: true, index: true },
    sender: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    recipient: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    group: { type: Schema.Types.ObjectId, ref: 'Group', default: null },
    text: { type: String, default: '', trim: true, maxlength: 4000 },
    imageUrl: { type: String, default: '', trim: true },
    readBy: { type: [ReadReceiptSchema], default: [] },
    deliveredTo: [{ type: Schema.Types.ObjectId, ref: 'User' }],
  },
  { timestamps: true }
);
MessageSchema.index({ conversationKey: 1, createdAt: -1 });
MessageSchema.index({ recipient: 1, chatType: 1, deliveredTo: 1 });
MessageSchema.index({ group: 1, chatType: 1, deliveredTo: 1 });

const PostSchema = new Schema(
  {
    author: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    group: { type: Schema.Types.ObjectId, ref: 'Group', default: null, index: true },
    content: { type: String, default: '', trim: true, maxlength: 5000 },
    imageUrl: { type: String, default: '', trim: true },
    likes: [{ type: Schema.Types.ObjectId, ref: 'User' }],
  },
  { timestamps: true }
);
PostSchema.index({ createdAt: -1 });

const FollowSchema = new Schema(
  {
    follower: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    targetType: { type: String, enum: ['user', 'group'], required: true },
    targetUser: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    targetGroup: { type: Schema.Types.ObjectId, ref: 'Group', default: null },
  },
  { timestamps: true }
);
FollowSchema.index(
  { follower: 1, targetUser: 1 },
  { unique: true, partialFilterExpression: { targetUser: { $type: 'objectId' } } }
);
FollowSchema.index(
  { follower: 1, targetGroup: 1 },
  { unique: true, partialFilterExpression: { targetGroup: { $type: 'objectId' } } }
);

const User = mongoose.models.User || mongoose.model('User', UserSchema);
const Group = mongoose.models.Group || mongoose.model('Group', GroupSchema);
const Message = mongoose.models.Message || mongoose.model('Message', MessageSchema);
const Post = mongoose.models.Post || mongoose.model('Post', PostSchema);
const Follow = mongoose.models.Follow || mongoose.model('Follow', FollowSchema);

// =============================================================================
// 3. HELPERS & VALIDATION
// =============================================================================

const INVITE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const USERNAME_REGEX = /^[a-zA-Z0-9_]{3,30}$/;

function isNonEmptyString(val) {
  return typeof val === 'string' && val.trim().length > 0;
}

function normalizeUsername(raw) {
  if (typeof raw !== 'string') return '';
  return raw.trim().replace(/^@+/, '');
}

function isValidObjectId(id) {
  return typeof id === 'string' && Types.ObjectId.isValid(id);
}

function isValidHttpUrl(url) {
  if (url === '') return true;
  if (typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function getDmKey(userIdA, userIdB) {
  return `dm:${[String(userIdA), String(userIdB)].sort().join(':')}`;
}

function toPublicUser(user) {
  if (!user) return null;
  const id = String(user._id);
  return {
    id,
    _id: id,
    username: user.username,
    handle: `@${user.username}`,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl || '',
    bio: user.bio || '',
    followersCount: user.followersCount || 0,
    followingCount: user.followingCount || 0,
    isOnline: Boolean(user.isOnline),
    lastSeenAt: user.lastSeenAt,
    createdAt: user.createdAt,
  };
}

function formatGroup(group, currentUserId) {
  const uid = currentUserId ? String(currentUserId) : '';
  const members = (group.members || []).map((m) => {
    const populated = m.user && m.user._id ? m.user : null;
    const memberId = populated ? String(populated._id) : String(m.user);
    return {
      user: populated ? toPublicUser(populated) : { id: memberId },
      role: m.role,
      joinedAt: m.joinedAt,
    };
  });
  const myEntry = members.find((m) => m.user.id === uid);
  return {
    id: String(group._id),
    _id: String(group._id),
    name: group.name,
    description: group.description || '',
    photoUrl: group.photoUrl || '',
    leaderId: String(group.leader?._id || group.leader),
    myRole: myEntry ? myEntry.role : null,
    memberCount: members.length,
    followersCount: group.followersCount || 0,
    members,
    createdAt: group.createdAt,
    updatedAt: group.updatedAt,
  };
}

function formatMessage(msg) {
  return {
    id: String(msg._id),
    _id: String(msg._id),
    chatType: msg.chatType,
    conversationKey: msg.conversationKey,
    sender: msg.sender && msg.sender._id ? toPublicUser(msg.sender) : { id: String(msg.sender) },
    recipientId: msg.recipient ? String(msg.recipient._id || msg.recipient) : null,
    groupId: msg.group ? String(msg.group._id || msg.group) : null,
    text: msg.text || '',
    imageUrl: msg.imageUrl || '',
    readBy: (msg.readBy || []).map((r) => ({
      userId: String(r.user?._id || r.user),
      readAt: r.readAt,
    })),
    deliveredTo: (msg.deliveredTo || []).map((id) => String(id?._id || id)),
    createdAt: msg.createdAt,
  };
}

function signToken(user) {
  return jwt.sign(
    {
      sub: String(user._id),
      username: user.username,
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function verifyImageMagicBytes(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return false;
  // JPEG: FF D8 FF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return true;
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47
  ) {
    return true;
  }
  // GIF: GIF87a or GIF89a
  if (
    buffer[0] === 0x47 &&
    buffer[1] === 0x49 &&
    buffer[2] === 0x46 &&
    buffer[3] === 0x38
  ) {
    return true;
  }
  // WebP: RIFF....WEBP
  if (
    buffer.subarray(0, 4).toString('ascii') === 'RIFF' &&
    buffer.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    return true;
  }
  return false;
}

// Track active Socket.IO connections per userId in memory
const onlineSockets = new Map(); // userId -> Set<socketId>

function addUserSocket(userId, socketId) {
  const uid = String(userId);
  if (!onlineSockets.has(uid)) onlineSockets.set(uid, new Set());
  onlineSockets.get(uid).add(socketId);
  return onlineSockets.get(uid).size;
}

function removeUserSocket(userId, socketId) {
  const uid = String(userId);
  const set = onlineSockets.get(uid);
  if (!set) return 0;
  set.delete(socketId);
  if (set.size === 0) {
    onlineSockets.delete(uid);
    return 0;
  }
  return set.size;
}

function isUserOnline(userId) {
  const set = onlineSockets.get(String(userId));
  return Boolean(set && set.size > 0);
}

async function buildUserBootstrap(userId) {
  const uid = new Types.ObjectId(String(userId));

  // 1. Load user's groups
  const groups = await Group.find({ 'members.user': uid })
    .populate('members.user', 'username displayName avatarUrl isOnline lastSeenAt')
    .sort({ updatedAt: -1 })
    .lean();

  const groupIds = groups.map((g) => g._id);

  // 2. Group unread counts & latest messages
  const groupSummaries = await Promise.all(
    groups.map(async (g) => {
      const convKey = `group:${String(g._id)}`;
      const [unreadCount, recentMsgs] = await Promise.all([
        Message.countDocuments({
          conversationKey: convKey,
          sender: { $ne: uid },
          'readBy.user': { $ne: uid },
        }),
        Message.find({ conversationKey: convKey })
          .sort({ createdAt: -1 })
          .limit(30)
          .populate('sender', 'username displayName avatarUrl isOnline lastSeenAt')
          .lean(),
      ]);
      const chronological = recentMsgs.reverse().map(formatMessage);
      return {
        ...formatGroup(g, userId),
        unreadCount,
        lastMessage: chronological[chronological.length - 1] || null,
        recentMessages: chronological,
      };
    })
  );

  // 3. DM conversations (all conversations involving uid)
  const dmAgg = await Message.aggregate([
    {
      $match: {
        chatType: 'dm',
        $or: [{ sender: uid }, { recipient: uid }],
      },
    },
    { $sort: { createdAt: -1 } },
    {
      $group: {
        _id: '$conversationKey',
        lastMessageId: { $first: '$_id' },
        lastMessageAt: { $first: '$createdAt' },
        peerId: {
          $first: {
            $cond: [{ $eq: ['$sender', uid] }, '$recipient', '$sender'],
          },
        },
        unreadCount: {
          $sum: {
            $cond: [
              {
                $and: [
                  { $ne: ['$sender', uid] },
                  {
                    $not: {
                      $in: [uid, '$readBy.user'],
                    },
                  },
                ],
              },
              1,
              0,
            ],
          },
        },
      },
    },
    { $sort: { lastMessageAt: -1 } },
    { $limit: 50 },
  ]);

  const peerIds = dmAgg.map((d) => d.peerId).filter(Boolean);
  const peers = await User.find({ _id: { $in: peerIds } }).lean();
  const peerMap = new Map(peers.map((p) => [String(p._id), toPublicUser(p)]));

  const dms = await Promise.all(
    dmAgg.map(async (conv) => {
      const recentMsgs = await Message.find({ conversationKey: conv._id })
        .sort({ createdAt: -1 })
        .limit(30)
        .populate('sender', 'username displayName avatarUrl isOnline lastSeenAt')
        .lean();
      const chronological = recentMsgs.reverse().map(formatMessage);
      return {
        conversationKey: conv._id,
        peer: peerMap.get(String(conv.peerId)) || { id: String(conv.peerId) },
        unreadCount: conv.unreadCount,
        lastMessage: chronological[chronological.length - 1] || null,
        recentMessages: chronological,
      };
    })
  );

  const totalUnread =
    dms.reduce((sum, d) => sum + d.unreadCount, 0) +
    groupSummaries.reduce((sum, g) => sum + g.unreadCount, 0);

  return {
    dms,
    groups: groupSummaries,
    groupIds: groupIds.map(String),
    totalUnread,
  };
}

// =============================================================================
// 4. EXPRESS APP, SECURITY MIDDLEWARE & RATE LIMITERS
// =============================================================================

const app = express();
const httpServer = http.createServer(app);

// Essential behind Render's reverse proxy so express-rate-limit uses real client IP
app.set('trust proxy', 1);

app.use(helmet());
app.use(cors({ origin: corsOriginCheck, credentials: false }));
app.use(express.json({ limit: '1mb' }));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please slow down.' },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many failed login attempts. Please wait 15 minutes before trying again.',
  },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many registration attempts. Please try again later.' },
});

app.use(apiLimiter);

// JWT Authentication Middleware
async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authorization Bearer token required' });
    }
    const token = authHeader.slice(7).trim();
    if (!token) {
      return res.status(401).json({ error: 'Empty authorization token' });
    }

    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload || !isValidObjectId(payload.sub)) {
      return res.status(401).json({ error: 'Invalid token payload' });
    }

    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(401).json({ error: 'Account no longer exists' });
    }

    req.user = user;
    next();
  } catch (err) {
    if (err?.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// =============================================================================
// 5. HEALTH CHECK
// =============================================================================

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    dbConnected: mongoose.connection.readyState === 1,
    cloudinaryConfigured: isCloudinaryConfigured(),
    uptimeSeconds: Math.round(process.uptime()),
  });
});

// =============================================================================
// 6. AUTH ROUTES (/auth/register, /auth/login, /auth/me)
// =============================================================================

app.post('/auth/register', registerLimiter, async (req, res) => {
  try {
    const rawUsername = req.body?.username ?? req.body?.handle;
    const rawPassword = req.body?.password;
    const rawDisplayName = req.body?.displayName;

    const username = normalizeUsername(rawUsername);
    if (!USERNAME_REGEX.test(username)) {
      return res.status(400).json({
        error:
          'Username (@id) must be 3-30 characters and contain only letters, numbers, or underscores.',
      });
    }

    if (typeof rawPassword !== 'string' || rawPassword.length < 8 || rawPassword.length > 128) {
      return res.status(400).json({
        error: 'Password must be between 8 and 128 characters.',
      });
    }

    if (!isNonEmptyString(rawDisplayName) || rawDisplayName.trim().length > 60) {
      return res.status(400).json({
        error: 'Display name is required and must be 60 characters or fewer.',
      });
    }

    const usernameLower = username.toLowerCase();
    const existing = await User.findOne({ usernameLower }).lean();
    if (existing) {
      return res.status(409).json({ error: 'Username is already taken.' });
    }

    const passwordHash = await bcrypt.hash(rawPassword, 12);
    const user = await User.create({
      username,
      usernameLower,
      displayName: rawDisplayName.trim(),
      passwordHash,
    });

    const token = signToken(user);
    return res.status(201).json({
      token,
      user: toPublicUser(user),
    });
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).json({ error: 'Username is already taken.' });
    }
    console.error('[POST /auth/register]', err);
    return res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/auth/login', loginLimiter, async (req, res) => {
  try {
    const rawUsername = req.body?.username ?? req.body?.handle;
    const rawPassword = req.body?.password;

    const username = normalizeUsername(rawUsername);
    if (!username) {
      return res.status(400).json({ error: 'Username is required.' });
    }
    if (typeof rawPassword !== 'string' || rawPassword.length === 0) {
      return res.status(400).json({ error: 'Password is required.' });
    }

    const user = await User.findOne({ usernameLower: username.toLowerCase() }).select(
      '+passwordHash'
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const passwordMatches = await bcrypt.compare(rawPassword, user.passwordHash);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Wrong password' });
    }

    const token = signToken(user);
    const bootstrap = await buildUserBootstrap(user._id);

    return res.json({
      token,
      user: toPublicUser(user),
      dms: bootstrap.dms,
      groups: bootstrap.groups,
      totalUnread: bootstrap.totalUnread,
    });
  } catch (err) {
    console.error('[POST /auth/login]', err);
    return res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const bootstrap = await buildUserBootstrap(req.user._id);
    return res.json({
      user: toPublicUser(req.user),
      dms: bootstrap.dms,
      groups: bootstrap.groups,
      totalUnread: bootstrap.totalUnread,
    });
  } catch (err) {
    console.error('[GET /auth/me]', err);
    return res.status(500).json({ error: 'Failed to load profile and chats' });
  }
});

// =============================================================================
// 7. USER PROFILE & DISCOVERY ROUTES
// =============================================================================

app.patch('/users/me', requireAuth, async (req, res) => {
  try {
    const updates = {};

    if (req.body?.displayName !== undefined) {
      if (!isNonEmptyString(req.body.displayName) || req.body.displayName.trim().length > 60) {
        return res.status(400).json({ error: 'Display name must be 1-60 characters.' });
      }
      updates.displayName = req.body.displayName.trim();
    }

    if (req.body?.bio !== undefined) {
      if (typeof req.body.bio !== 'string' || req.body.bio.trim().length > 240) {
        return res.status(400).json({ error: 'Bio must be 240 characters or fewer.' });
      }
      updates.bio = req.body.bio.trim();
    }

    if (req.body?.avatarUrl !== undefined) {
      if (!isValidHttpUrl(req.body.avatarUrl)) {
        return res.status(400).json({ error: 'avatarUrl must be a valid HTTP(S) URL.' });
      }
      updates.avatarUrl = req.body.avatarUrl.trim();
    }

    const updated = await User.findByIdAndUpdate(
      req.user._id,
      { $set: updates },
      { new: true }
    );
    return res.json({ user: toPublicUser(updated) });
  } catch (err) {
    console.error('[PATCH /users/me]', err);
    return res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.get('/users/search', requireAuth, async (req, res) => {
  try {
    const q = typeof req.query.q === 'string' ? req.query.q.trim().replace(/^@+/, '') : '';
    if (!q) {
      const recent = await User.find({ _id: { $ne: req.user._id } })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean();
      return res.json({ users: recent.map(toPublicUser) });
    }

    const regex = new RegExp(escapeRegex(q), 'i');
    const users = await User.find({
      _id: { $ne: req.user._id },
      $or: [{ usernameLower: regex }, { displayName: regex }],
    })
      .limit(20)
      .lean();

    return res.json({ users: users.map(toPublicUser) });
  } catch (err) {
    console.error('[GET /users/search]', err);
    return res.status(500).json({ error: 'User search failed' });
  }
});

app.get('/users/:userId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    const target = await User.findById(req.params.userId).lean();
    if (!target) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isFollowing = Boolean(
      await Follow.exists({
        follower: req.user._id,
        targetType: 'user',
        targetUser: target._id,
      })
    );

    return res.json({ user: toPublicUser(target), isFollowing });
  } catch (err) {
    console.error('[GET /users/:userId]', err);
    return res.status(500).json({ error: 'Failed to load user' });
  }
});

// =============================================================================
// 8. PHOTO UPLOAD (POST /upload — Multer Memory + Cloudinary, Max 5 MB, Images Only)
// =============================================================================

const ALLOWED_IMAGE_MIMES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5 MB
    files: 1,
  },
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_IMAGE_MIMES.has(file.mimetype)) {
      return cb(new Error('Only JPEG, PNG, WebP, and GIF images are allowed.'));
    }
    return cb(null, true);
  },
});

function uploadToCloudinary(buffer, folder = 'chat_app') {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder,
        resource_type: 'image',
        transformation: [{ quality: 'auto', fetch_format: 'auto' }],
      },
      (error, result) => {
        if (error) return reject(error);
        return resolve(result);
      }
    );
    stream.end(buffer);
  });
}

app.post('/upload', requireAuth, (req, res) => {
  upload.single('file')(req, res, async (multerErr) => {
    try {
      if (multerErr) {
        if (multerErr.code === 'LIMIT_FILE_SIZE') {
          return res.status(413).json({ error: 'Image exceeds maximum size of 5 MB.' });
        }
        return res.status(400).json({ error: multerErr.message || 'Invalid file upload.' });
      }

      if (!req.file) {
        return res
          .status(400)
          .json({ error: 'No image file provided. Send multipart/form-data field "file".' });
      }

      if (!verifyImageMagicBytes(req.file.buffer)) {
        return res.status(400).json({ error: 'File contents are not a valid image.' });
      }

      if (!isCloudinaryConfigured()) {
        return res.status(503).json({
          error:
            'Cloudinary is not configured on the server. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET.',
        });
      }

      const folderRaw = typeof req.body?.purpose === 'string' ? req.body.purpose : 'general';
      const safeFolder = ['profile', 'group', 'post', 'chat'].includes(folderRaw)
        ? `chat_app/${folderRaw}`
        : 'chat_app/general';

      const result = await uploadToCloudinary(req.file.buffer, safeFolder);

      return res.status(201).json({
        url: result.secure_url,
        publicId: result.public_id,
        width: result.width,
        height: result.height,
        bytes: result.bytes,
        format: result.format,
      });
    } catch (err) {
      console.error('[POST /upload]', err);
      return res.status(500).json({ error: 'Image upload failed' });
    }
  });
});

// =============================================================================
// 9. CHAT & MESSAGE ROUTES (Persistent DM & Group Messages + Unread Counts)
// =============================================================================

app.get('/chats', requireAuth, async (req, res) => {
  try {
    const bootstrap = await buildUserBootstrap(req.user._id);
    return res.json({
      dms: bootstrap.dms,
      groups: bootstrap.groups,
      totalUnread: bootstrap.totalUnread,
    });
  } catch (err) {
    console.error('[GET /chats]', err);
    return res.status(500).json({ error: 'Failed to load chats' });
  }
});

app.get('/messages/dm/:peerId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.peerId)) {
      return res.status(400).json({ error: 'Invalid peer user ID' });
    }
    const peer = await User.findById(req.params.peerId).lean();
    if (!peer) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
    const filter = { conversationKey: getDmKey(req.user._id, peer._id) };
    if (typeof req.query.before === 'string' && !Number.isNaN(Date.parse(req.query.before))) {
      filter.createdAt = { $lt: new Date(req.query.before) };
    }

    const messages = await Message.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate('sender', 'username displayName avatarUrl isOnline lastSeenAt')
      .lean();

    return res.json({
      peer: toPublicUser(peer),
      messages: messages.reverse().map(formatMessage),
    });
  } catch (err) {
    console.error('[GET /messages/dm/:peerId]', err);
    return res.status(500).json({ error: 'Failed to load DM history' });
  }
});

app.get('/messages/group/:groupId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.groupId)) {
      return res.status(400).json({ error: 'Invalid group ID' });
    }

    const isMember = await Group.exists({
      _id: req.params.groupId,
      'members.user': req.user._id,
    });
    if (!isMember) {
      return res.status(403).json({ error: 'You must be a member of this group to view messages.' });
    }

    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
    const filter = { conversationKey: `group:${req.params.groupId}` };
    if (typeof req.query.before === 'string' && !Number.isNaN(Date.parse(req.query.before))) {
      filter.createdAt = { $lt: new Date(req.query.before) };
    }

    const messages = await Message.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate('sender', 'username displayName avatarUrl isOnline lastSeenAt')
      .lean();

    return res.json({
      groupId: req.params.groupId,
      messages: messages.reverse().map(formatMessage),
    });
  } catch (err) {
    console.error('[GET /messages/group/:groupId]', err);
    return res.status(500).json({ error: 'Failed to load group history' });
  }
});

async function createAndDispatchDm({ senderUser, recipientId, text, imageUrl }) {
  const recipient = await User.findById(recipientId);
  if (!recipient) {
    return { error: 'Recipient not found', status: 404 };
  }

  const deliveredTo = [senderUser._id];
  if (isUserOnline(recipient._id)) {
    deliveredTo.push(recipient._id);
  }

  const msg = await Message.create({
    chatType: 'dm',
    conversationKey: getDmKey(senderUser._id, recipient._id),
    sender: senderUser._id,
    recipient: recipient._id,
    text,
    imageUrl,
    readBy: [{ user: senderUser._id, readAt: new Date() }],
    deliveredTo,
  });

  await msg.populate('sender', 'username displayName avatarUrl isOnline lastSeenAt');
  const formatted = formatMessage(msg);

  io.to(`user:${String(recipient._id)}`).emit('new_dm', formatted);
  io.to(`user:${String(recipient._id)}`).emit('private_message', formatted);
  io.to(`user:${String(senderUser._id)}`).emit('new_dm', formatted);

  return { message: formatted };
}

async function createAndDispatchGroupMessage({ senderUser, groupId, text, imageUrl }) {
  const group = await Group.findOne({ _id: groupId, 'members.user': senderUser._id });
  if (!group) {
    return { error: 'Group not found or you are not a member.', status: 403 };
  }

  const deliveredTo = [senderUser._id];
  for (const m of group.members) {
    const memberIdStr = String(m.user);
    if (memberIdStr !== String(senderUser._id) && isUserOnline(memberIdStr)) {
      deliveredTo.push(m.user);
    }
  }

  const msg = await Message.create({
    chatType: 'group',
    conversationKey: `group:${String(group._id)}`,
    sender: senderUser._id,
    group: group._id,
    text,
    imageUrl,
    readBy: [{ user: senderUser._id, readAt: new Date() }],
    deliveredTo,
  });

  await msg.populate('sender', 'username displayName avatarUrl isOnline lastSeenAt');
  const formatted = formatMessage(msg);

  io.to(`group:${String(group._id)}`).emit('new_group_message', formatted);
  io.to(`group:${String(group._id)}`).emit('group_message', formatted);

  return { message: formatted };
}

app.post('/messages/dm/:peerId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.peerId)) {
      return res.status(400).json({ error: 'Invalid peer user ID' });
    }
    const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
    const imageUrl = typeof req.body?.imageUrl === 'string' ? req.body.imageUrl.trim() : '';

    if (!text && !imageUrl) {
      return res.status(400).json({ error: 'Message must include text or imageUrl.' });
    }
    if (!isValidHttpUrl(imageUrl)) {
      return res.status(400).json({ error: 'Invalid imageUrl' });
    }

    const result = await createAndDispatchDm({
      senderUser: req.user,
      recipientId: req.params.peerId,
      text,
      imageUrl,
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    return res.status(201).json({ message: result.message });
  } catch (err) {
    console.error('[POST /messages/dm/:peerId]', err);
    return res.status(500).json({ error: 'Failed to send DM' });
  }
});

app.post('/messages/group/:groupId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.groupId)) {
      return res.status(400).json({ error: 'Invalid group ID' });
    }
    const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
    const imageUrl = typeof req.body?.imageUrl === 'string' ? req.body.imageUrl.trim() : '';

    if (!text && !imageUrl) {
      return res.status(400).json({ error: 'Message must include text or imageUrl.' });
    }
    if (!isValidHttpUrl(imageUrl)) {
      return res.status(400).json({ error: 'Invalid imageUrl' });
    }

    const result = await createAndDispatchGroupMessage({
      senderUser: req.user,
      groupId: req.params.groupId,
      text,
      imageUrl,
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    return res.status(201).json({ message: result.message });
  } catch (err) {
    console.error('[POST /messages/group/:groupId]', err);
    return res.status(500).json({ error: 'Failed to send group message' });
  }
});

async function markMessagesRead({ userId, chatType, peerId, groupId, messageIds }) {
  let conversationKey = null;
  if (chatType === 'dm' && isValidObjectId(peerId)) {
    conversationKey = getDmKey(userId, peerId);
  } else if (chatType === 'group' && isValidObjectId(groupId)) {
    const isMember = await Group.exists({ _id: groupId, 'members.user': userId });
    if (!isMember) return { error: 'Not a member of this group', status: 403 };
    conversationKey = `group:${groupId}`;
  } else {
    return { error: 'Provide chatType ("dm" or "group") and valid peerId/groupId', status: 400 };
  }

  const filter = {
    conversationKey,
    sender: { $ne: userId },
    'readBy.user': { $ne: userId },
  };
  if (Array.isArray(messageIds) && messageIds.length > 0) {
    const validIds = messageIds.filter(isValidObjectId);
    if (validIds.length > 0) filter._id = { $in: validIds };
  }

  const readAt = new Date();
  const updateResult = await Message.updateMany(filter, {
    $push: { readBy: { user: userId, readAt } },
  });

  const payload = {
    chatType,
    conversationKey,
    readerId: String(userId),
    peerId: peerId ? String(peerId) : null,
    groupId: groupId ? String(groupId) : null,
    readAt,
    updatedCount: updateResult.modifiedCount,
  };

  if (chatType === 'dm') {
    io.to(`user:${String(peerId)}`).emit('messages_read', payload);
    io.to(`user:${String(userId)}`).emit('messages_read', payload);
  } else {
    io.to(`group:${String(groupId)}`).emit('messages_read', payload);
  }

  return payload;
}

app.post('/messages/read', requireAuth, async (req, res) => {
  try {
    const result = await markMessagesRead({
      userId: req.user._id,
      chatType: req.body?.chatType,
      peerId: req.body?.peerId,
      groupId: req.body?.groupId,
      messageIds: req.body?.messageIds,
    });
    if (result.error) return res.status(result.status).json({ error: result.error });
    return res.json(result);
  } catch (err) {
    console.error('[POST /messages/read]', err);
    return res.status(500).json({ error: 'Failed to mark messages as read' });
  }
});

// =============================================================================
// 10. GROUP ROUTES (Unique Names, 30-Day Invites, Leader/Member Roles)
// =============================================================================

app.post('/groups', requireAuth, async (req, res) => {
  try {
    const rawName = req.body?.name;
    const rawDescription = req.body?.description ?? '';
    const rawPhotoUrl = req.body?.photoUrl ?? '';

    if (!isNonEmptyString(rawName)) {
      return res.status(400).json({ error: 'Group name is required.' });
    }
    const name = rawName.trim();
    if (name.length < 2 || name.length > 80) {
      return res.status(400).json({ error: 'Group name must be between 2 and 80 characters.' });
    }
    if (typeof rawDescription !== 'string' || rawDescription.trim().length > 400) {
      return res.status(400).json({ error: 'Description must be 400 characters or fewer.' });
    }
    if (!isValidHttpUrl(rawPhotoUrl)) {
      return res.status(400).json({ error: 'photoUrl must be a valid HTTP(S) URL.' });
    }

    const nameLower = name.toLowerCase();
    const existing = await Group.findOne({ nameLower }).lean();
    if (existing) {
      return res.status(409).json({ error: 'A group with this name already exists.' });
    }

    const inviteCode = crypto.randomBytes(16).toString('hex');
    const inviteExpiresAt = new Date(Date.now() + INVITE_TTL_MS);

    const group = await Group.create({
      name,
      nameLower,
      description: rawDescription.trim(),
      photoUrl: rawPhotoUrl.trim(),
      leader: req.user._id,
      members: [{ user: req.user._id, role: 'leader', joinedAt: new Date() }],
      inviteCode,
      inviteExpiresAt,
      inviteCreatedBy: req.user._id,
    });

    await group.populate('members.user', 'username displayName avatarUrl isOnline lastSeenAt');

    // Join all active sockets of the creator to the group room
    io.in(`user:${String(req.user._id)}`).socketsJoin(`group:${String(group._id)}`);

    return res.status(201).json({
      group: formatGroup(group, req.user._id),
      inviteCode,
      invitePath: `/groups/join/${inviteCode}`,
      inviteExpiresAt,
    });
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).json({ error: 'A group with this name already exists.' });
    }
    console.error('[POST /groups]', err);
    return res.status(500).json({ error: 'Failed to create group' });
  }
});

app.get('/groups', requireAuth, async (req, res) => {
  try {
    const discover = req.query.discover === 'true';
    const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';

    const filter = discover ? {} : { 'members.user': req.user._id };
    if (q) {
      filter.nameLower = new RegExp(escapeRegex(q.toLowerCase()), 'i');
    }

    const groups = await Group.find(filter)
      .populate('members.user', 'username displayName avatarUrl isOnline lastSeenAt')
      .sort({ updatedAt: -1 })
      .limit(50)
      .lean();

    return res.json({
      groups: groups.map((g) => formatGroup(g, req.user._id)),
    });
  } catch (err) {
    console.error('[GET /groups]', err);
    return res.status(500).json({ error: 'Failed to load groups' });
  }
});

app.get('/groups/invite/:code', requireAuth, async (req, res) => {
  try {
    const code = typeof req.params.code === 'string' ? req.params.code.trim() : '';
    const group = await Group.findOne({ inviteCode: code }).lean();
    if (!group) {
      return res.status(404).json({ error: 'Invite link not found' });
    }
    if (!group.inviteExpiresAt || new Date(group.inviteExpiresAt) <= new Date()) {
      return res.status(410).json({ error: 'Invite link has expired' });
    }

    return res.json({
      group: {
        id: String(group._id),
        name: group.name,
        description: group.description || '',
        photoUrl: group.photoUrl || '',
        memberCount: group.members.length,
        followersCount: group.followersCount || 0,
        expiresAt: group.inviteExpiresAt,
      },
    });
  } catch (err) {
    console.error('[GET /groups/invite/:code]', err);
    return res.status(500).json({ error: 'Failed to validate invite link' });
  }
});

app.post('/groups/join/:code', requireAuth, async (req, res) => {
  try {
    const code = typeof req.params.code === 'string' ? req.params.code.trim() : '';
    const group = await Group.findOne({ inviteCode: code });
    if (!group) {
      return res.status(404).json({ error: 'Invite link not found' });
    }
    if (!group.inviteExpiresAt || group.inviteExpiresAt <= new Date()) {
      return res.status(410).json({ error: 'Invite link has expired' });
    }

    const alreadyMember = group.members.some(
      (m) => String(m.user) === String(req.user._id)
    );

    if (!alreadyMember) {
      group.members.push({ user: req.user._id, role: 'member', joinedAt: new Date() });
      await group.save();
    }

    await group.populate('members.user', 'username displayName avatarUrl isOnline lastSeenAt');

    io.in(`user:${String(req.user._id)}`).socketsJoin(`group:${String(group._id)}`);
    if (!alreadyMember) {
      io.to(`group:${String(group._id)}`).emit('group_member_joined', {
        groupId: String(group._id),
        user: toPublicUser(req.user),
        role: 'member',
      });
    }

    return res.json({
      joined: !alreadyMember,
      group: formatGroup(group, req.user._id),
    });
  } catch (err) {
    console.error('[POST /groups/join/:code]', err);
    return res.status(500).json({ error: 'Failed to join group' });
  }
});

app.get('/groups/:groupId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.groupId)) {
      return res.status(400).json({ error: 'Invalid group ID' });
    }
    const group = await Group.findById(req.params.groupId)
      .populate('members.user', 'username displayName avatarUrl isOnline lastSeenAt')
      .lean();
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }

    const isFollowing = Boolean(
      await Follow.exists({
        follower: req.user._id,
        targetType: 'group',
        targetGroup: group._id,
      })
    );

    return res.json({
      group: formatGroup(group, req.user._id),
      isFollowing,
    });
  } catch (err) {
    console.error('[GET /groups/:groupId]', err);
    return res.status(500).json({ error: 'Failed to load group' });
  }
});

function isGroupLeader(group, userId) {
  const uid = String(userId);
  return group.members.some((m) => String(m.user?._id || m.user) === uid && m.role === 'leader');
}

app.patch('/groups/:groupId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.groupId)) {
      return res.status(400).json({ error: 'Invalid group ID' });
    }
    const group = await Group.findById(req.params.groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    if (!isGroupLeader(group, req.user._id)) {
      return res.status(403).json({ error: 'Only group leaders can edit group settings.' });
    }

    if (req.body?.name !== undefined) {
      if (!isNonEmptyString(req.body.name)) {
        return res.status(400).json({ error: 'Group name cannot be empty.' });
      }
      const trimmed = req.body.name.trim();
      if (trimmed.length < 2 || trimmed.length > 80) {
        return res.status(400).json({ error: 'Group name must be 2-80 characters.' });
      }
      const nameLower = trimmed.toLowerCase();
      const duplicate = await Group.findOne({ nameLower, _id: { $ne: group._id } }).lean();
      if (duplicate) {
        return res.status(409).json({ error: 'A group with this name already exists.' });
      }
      group.name = trimmed;
      group.nameLower = nameLower;
    }

    if (req.body?.description !== undefined) {
      if (typeof req.body.description !== 'string' || req.body.description.trim().length > 400) {
        return res.status(400).json({ error: 'Description must be 400 characters or fewer.' });
      }
      group.description = req.body.description.trim();
    }

    if (req.body?.photoUrl !== undefined) {
      if (!isValidHttpUrl(req.body.photoUrl)) {
        return res.status(400).json({ error: 'photoUrl must be a valid HTTP(S) URL.' });
      }
      group.photoUrl = req.body.photoUrl.trim();
    }

    await group.save();
    await group.populate('members.user', 'username displayName avatarUrl isOnline lastSeenAt');

    const formatted = formatGroup(group, req.user._id);
    io.to(`group:${String(group._id)}`).emit('group_updated', formatted);

    return res.json({ group: formatted });
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).json({ error: 'A group with this name already exists.' });
    }
    console.error('[PATCH /groups/:groupId]', err);
    return res.status(500).json({ error: 'Failed to update group' });
  }
});

app.post('/groups/:groupId/invite', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.groupId)) {
      return res.status(400).json({ error: 'Invalid group ID' });
    }
    const group = await Group.findById(req.params.groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    if (!isGroupLeader(group, req.user._id)) {
      return res.status(403).json({ error: 'Only group leaders can generate invite links.' });
    }

    group.inviteCode = crypto.randomBytes(16).toString('hex');
    group.inviteExpiresAt = new Date(Date.now() + INVITE_TTL_MS);
    group.inviteCreatedBy = req.user._id;
    await group.save();

    return res.json({
      groupId: String(group._id),
      inviteCode: group.inviteCode,
      invitePath: `/groups/join/${group.inviteCode}`,
      expiresAt: group.inviteExpiresAt,
    });
  } catch (err) {
    console.error('[POST /groups/:groupId/invite]', err);
    return res.status(500).json({ error: 'Failed to create invite link' });
  }
});

app.patch('/groups/:groupId/members/:memberId/role', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.groupId) || !isValidObjectId(req.params.memberId)) {
      return res.status(400).json({ error: 'Invalid ID' });
    }
    const role = req.body?.role;
    if (role !== 'leader' && role !== 'member') {
      return res.status(400).json({ error: 'Role must be "leader" or "member".' });
    }

    const group = await Group.findById(req.params.groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    if (!isGroupLeader(group, req.user._id)) {
      return res.status(403).json({ error: 'Only group leaders can change member roles.' });
    }

    const member = group.members.find((m) => String(m.user) === req.params.memberId);
    if (!member) {
      return res.status(404).json({ error: 'Member not found in group' });
    }

    if (role === 'member') {
      const leaderCount = group.members.filter((m) => m.role === 'leader').length;
      if (member.role === 'leader' && leaderCount <= 1) {
        return res
          .status(400)
          .json({ error: 'Group must have at least one leader. Promote another member first.' });
      }
    }

    member.role = role;
    await group.save();
    await group.populate('members.user', 'username displayName avatarUrl isOnline lastSeenAt');

    const formatted = formatGroup(group, req.user._id);
    io.to(`group:${String(group._id)}`).emit('group_updated', formatted);

    return res.json({ group: formatted });
  } catch (err) {
    console.error('[PATCH /groups/:groupId/members/:memberId/role]', err);
    return res.status(500).json({ error: 'Failed to update member role' });
  }
});

app.delete('/groups/:groupId/leave', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.groupId)) {
      return res.status(400).json({ error: 'Invalid group ID' });
    }
    const group = await Group.findById(req.params.groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }

    const idx = group.members.findIndex((m) => String(m.user) === String(req.user._id));
    if (idx === -1) {
      return res.status(400).json({ error: 'You are not a member of this group.' });
    }

    const leavingMember = group.members[idx];
    const remaining = group.members.filter((m) => String(m.user) !== String(req.user._id));

    if (remaining.length === 0) {
      await Group.deleteOne({ _id: group._id });
      await Follow.deleteMany({ targetType: 'group', targetGroup: group._id });
      io.in(`user:${String(req.user._id)}`).socketsLeave(`group:${String(group._id)}`);
      return res.json({ left: true, deletedEmptyGroup: true });
    }

    if (
      leavingMember.role === 'leader' &&
      !remaining.some((m) => m.role === 'leader')
    ) {
      remaining[0].role = 'leader';
      group.leader = remaining[0].user;
    }

    group.members = remaining;
    await group.save();

    io.in(`user:${String(req.user._id)}`).socketsLeave(`group:${String(group._id)}`);
    io.to(`group:${String(group._id)}`).emit('group_member_left', {
      groupId: String(group._id),
      userId: String(req.user._id),
    });

    return res.json({ left: true, deletedEmptyGroup: false });
  } catch (err) {
    console.error('[DELETE /groups/:groupId/leave]', err);
    return res.status(500).json({ error: 'Failed to leave group' });
  }
});

// =============================================================================
// 11. FOLLOW / UNFOLLOW ROUTES (Users & Groups with Counts)
// =============================================================================

app.post('/follows/users/:userId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    if (req.params.userId === String(req.user._id)) {
      return res.status(400).json({ error: 'You cannot follow yourself.' });
    }

    const target = await User.findById(req.params.userId);
    if (!target) {
      return res.status(404).json({ error: 'User not found' });
    }

    const existing = await Follow.findOne({
      follower: req.user._id,
      targetType: 'user',
      targetUser: target._id,
    });

    if (!existing) {
      await Follow.create({
        follower: req.user._id,
        targetType: 'user',
        targetUser: target._id,
      });
      await Promise.all([
        User.updateOne({ _id: target._id }, { $inc: { followersCount: 1 } }),
        User.updateOne({ _id: req.user._id }, { $inc: { followingCount: 1 } }),
      ]);
    }

    const refreshed = await User.findById(target._id).lean();
    return res.json({
      following: true,
      followersCount: refreshed.followersCount,
    });
  } catch (err) {
    if (err?.code === 11000) {
      const refreshed = await User.findById(req.params.userId).lean();
      return res.json({ following: true, followersCount: refreshed?.followersCount || 0 });
    }
    console.error('[POST /follows/users/:userId]', err);
    return res.status(500).json({ error: 'Failed to follow user' });
  }
});

app.delete('/follows/users/:userId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    const deleted = await Follow.findOneAndDelete({
      follower: req.user._id,
      targetType: 'user',
      targetUser: req.params.userId,
    });

    if (deleted) {
      await Promise.all([
        User.updateOne(
          { _id: req.params.userId, followersCount: { $gt: 0 } },
          { $inc: { followersCount: -1 } }
        ),
        User.updateOne(
          { _id: req.user._id, followingCount: { $gt: 0 } },
          { $inc: { followingCount: -1 } }
        ),
      ]);
    }

    const refreshed = await User.findById(req.params.userId).lean();
    return res.json({
      following: false,
      followersCount: refreshed?.followersCount || 0,
    });
  } catch (err) {
    console.error('[DELETE /follows/users/:userId]', err);
    return res.status(500).json({ error: 'Failed to unfollow user' });
  }
});

app.post('/follows/groups/:groupId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.groupId)) {
      return res.status(400).json({ error: 'Invalid group ID' });
    }
    const group = await Group.findById(req.params.groupId);
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }

    const existing = await Follow.findOne({
      follower: req.user._id,
      targetType: 'group',
      targetGroup: group._id,
    });

    if (!existing) {
      await Follow.create({
        follower: req.user._id,
        targetType: 'group',
        targetGroup: group._id,
      });
      await Group.updateOne({ _id: group._id }, { $inc: { followersCount: 1 } });
    }

    const refreshed = await Group.findById(group._id).lean();
    return res.json({
      following: true,
      followersCount: refreshed.followersCount,
    });
  } catch (err) {
    if (err?.code === 11000) {
      const refreshed = await Group.findById(req.params.groupId).lean();
      return res.json({ following: true, followersCount: refreshed?.followersCount || 0 });
    }
    console.error('[POST /follows/groups/:groupId]', err);
    return res.status(500).json({ error: 'Failed to follow group' });
  }
});

app.delete('/follows/groups/:groupId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.groupId)) {
      return res.status(400).json({ error: 'Invalid group ID' });
    }

    const deleted = await Follow.findOneAndDelete({
      follower: req.user._id,
      targetType: 'group',
      targetGroup: req.params.groupId,
    });

    if (deleted) {
      await Group.updateOne(
        { _id: req.params.groupId, followersCount: { $gt: 0 } },
        { $inc: { followersCount: -1 } }
      );
    }

    const refreshed = await Group.findById(req.params.groupId).lean();
    return res.json({
      following: false,
      followersCount: refreshed?.followersCount || 0,
    });
  } catch (err) {
    console.error('[DELETE /follows/groups/:groupId]', err);
    return res.status(500).json({ error: 'Failed to unfollow group' });
  }
});

// =============================================================================
// 12. POSTS ROUTES (Create, Feed, Like, Delete)
// =============================================================================

app.post('/posts', requireAuth, async (req, res) => {
  try {
    const content = typeof req.body?.content === 'string' ? req.body.content.trim() : '';
    const imageUrl = typeof req.body?.imageUrl === 'string' ? req.body.imageUrl.trim() : '';
    const groupId = req.body?.groupId ?? null;

    if (!content && !imageUrl) {
      return res.status(400).json({ error: 'Post must contain content or an imageUrl.' });
    }
    if (!isValidHttpUrl(imageUrl)) {
      return res.status(400).json({ error: 'Invalid imageUrl' });
    }

    let validGroupId = null;
    if (groupId !== null && groupId !== '') {
      if (!isValidObjectId(groupId)) {
        return res.status(400).json({ error: 'Invalid groupId' });
      }
      const isMember = await Group.exists({ _id: groupId, 'members.user': req.user._id });
      if (!isMember) {
        return res.status(403).json({ error: 'You must join the group before posting in it.' });
      }
      validGroupId = groupId;
    }

    const post = await Post.create({
      author: req.user._id,
      group: validGroupId,
      content,
      imageUrl,
    });

    await post.populate('author', 'username displayName avatarUrl');

    const formatted = {
      id: String(post._id),
      author: toPublicUser(post.author),
      groupId: post.group ? String(post.group) : null,
      content: post.content,
      imageUrl: post.imageUrl,
      likesCount: 0,
      likedByMe: false,
      createdAt: post.createdAt,
    };

    if (validGroupId) {
      io.to(`group:${String(validGroupId)}`).emit('new_post', formatted);
    }

    return res.status(201).json({ post: formatted });
  } catch (err) {
    console.error('[POST /posts]', err);
    return res.status(500).json({ error: 'Failed to create post' });
  }
});

app.get('/posts', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 30, 1), 100);
    const scope = typeof req.query.scope === 'string' ? req.query.scope : 'feed';
    const groupId = typeof req.query.groupId === 'string' ? req.query.groupId : '';

    let filter = {};
    if (groupId) {
      if (!isValidObjectId(groupId)) {
        return res.status(400).json({ error: 'Invalid groupId' });
      }
      filter = { group: groupId };
    } else if (scope !== 'all') {
      const follows = await Follow.find({ follower: req.user._id }).lean();
      const followedUserIds = follows
        .filter((f) => f.targetType === 'user' && f.targetUser)
        .map((f) => f.targetUser);
      const followedGroupIds = follows
        .filter((f) => f.targetType === 'group' && f.targetGroup)
        .map((f) => f.targetGroup);

      const memberGroups = await Group.find({ 'members.user': req.user._id }).select('_id').lean();
      const groupIds = [...followedGroupIds, ...memberGroups.map((g) => g._id)];

      filter = {
        $or: [
          { author: { $in: [req.user._id, ...followedUserIds] } },
          { group: { $in: groupIds } },
        ],
      };
    }

    const posts = await Post.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate('author', 'username displayName avatarUrl')
      .lean();

    const uid = String(req.user._id);
    return res.json({
      posts: posts.map((p) => ({
        id: String(p._id),
        author: toPublicUser(p.author),
        groupId: p.group ? String(p.group) : null,
        content: p.content,
        imageUrl: p.imageUrl,
        likesCount: (p.likes || []).length,
        likedByMe: (p.likes || []).some((id) => String(id) === uid),
        createdAt: p.createdAt,
      })),
    });
  } catch (err) {
    console.error('[GET /posts]', err);
    return res.status(500).json({ error: 'Failed to load posts' });
  }
});

app.post('/posts/:postId/like', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.postId)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }
    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const uid = String(req.user._id);
    const alreadyLiked = post.likes.some((id) => String(id) === uid);

    if (alreadyLiked) {
      post.likes = post.likes.filter((id) => String(id) !== uid);
    } else {
      post.likes.push(req.user._id);
    }
    await post.save();

    return res.json({
      liked: !alreadyLiked,
      likesCount: post.likes.length,
    });
  } catch (err) {
    console.error('[POST /posts/:postId/like]', err);
    return res.status(500).json({ error: 'Failed to toggle like' });
  }
});

app.delete('/posts/:postId', requireAuth, async (req, res) => {
  try {
    if (!isValidObjectId(req.params.postId)) {
      return res.status(400).json({ error: 'Invalid post ID' });
    }
    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    if (String(post.author) !== String(req.user._id)) {
      return res.status(403).json({ error: 'You can only delete your own posts.' });
    }
    await Post.deleteOne({ _id: post._id });
    return res.json({ deleted: true });
  } catch (err) {
    console.error('[DELETE /posts/:postId]', err);
    return res.status(500).json({ error: 'Failed to delete post' });
  }
});

// =============================================================================
// 13. SOCKET.IO SERVER WITH JWT AUTHENTICATION & OFFLINE DELIVERY
// =============================================================================

const io = new Server(httpServer, {
  cors: {
    origin: corsOriginCheck,
    methods: ['GET', 'POST'],
  },
});

io.use(async (socket, next) => {
  try {
    const authToken =
      typeof socket.handshake.auth?.token === 'string'
        ? socket.handshake.auth.token
        : '';
    const headerAuth =
      typeof socket.handshake.headers?.authorization === 'string'
        ? socket.handshake.headers.authorization
        : '';

    const rawToken = authToken || (headerAuth.startsWith('Bearer ') ? headerAuth.slice(7) : '');
    if (!rawToken) {
      return next(new Error('Authentication error: JWT token required'));
    }

    const payload = jwt.verify(rawToken.trim(), JWT_SECRET);
    if (!payload || !isValidObjectId(payload.sub)) {
      return next(new Error('Authentication error: Invalid token'));
    }

    const user = await User.findById(payload.sub);
    if (!user) {
      return next(new Error('Authentication error: Account not found'));
    }

    socket.user = user;
    return next();
  } catch {
    return next(new Error('Authentication error: Invalid or expired token'));
  }
});

io.on('connection', async (socket) => {
  const user = socket.user;
  const userId = String(user._id);

  try {
    // Join personal room for DMs and direct events
    socket.join(`user:${userId}`);

    const socketCount = addUserSocket(userId, socket.id);
    if (socketCount === 1) {
      await User.updateOne(
        { _id: user._id },
        { $set: { isOnline: true, lastSeenAt: new Date() } }
      );
      io.emit('user_status', { userId, isOnline: true, lastSeenAt: new Date() });
    }

    // Load persistent bootstrap state (DMs, groups, unread counts, recent history)
    const bootstrap = await buildUserBootstrap(user._id);

    // Join all group rooms the user belongs to
    for (const gid of bootstrap.groupIds) {
      socket.join(`group:${gid}`);
    }

    socket.emit('bootstrap', {
      user: toPublicUser(user),
      dms: bootstrap.dms,
      groups: bootstrap.groups,
      totalUnread: bootstrap.totalUnread,
    });

    // Deliver any messages stored while user was offline
    const groupObjectIds = bootstrap.groupIds.map((id) => new Types.ObjectId(id));
    const offlineDocs = await Message.find({
      sender: { $ne: user._id },
      deliveredTo: { $ne: user._id },
      $or: [
        { chatType: 'dm', recipient: user._id },
        { chatType: 'group', group: { $in: groupObjectIds } },
      ],
    })
      .sort({ createdAt: 1 })
      .limit(200)
      .populate('sender', 'username displayName avatarUrl isOnline lastSeenAt');

    if (offlineDocs.length > 0) {
      const formattedOffline = offlineDocs.map(formatMessage);
      socket.emit('offline_messages', { messages: formattedOffline });

      // Also replay standard message events for legacy listeners
      for (const msg of formattedOffline) {
        const eventName = msg.chatType === 'dm' ? 'private_message' : 'group_message';
        socket.emit(eventName, { ...msg, isOfflineReplay: true });
      }

      await Message.updateMany(
        { _id: { $in: offlineDocs.map((d) => d._id) } },
        { $addToSet: { deliveredTo: user._id } }
      );
    }
  } catch (err) {
    console.error('[Socket connection init]', err);
  }

  // Send Direct Message (supports both "send_dm" and "private_message" event names)
  async function handleSendDm(data, ack) {
    try {
      const toUserId = data?.toUserId ?? data?.recipientId ?? data?.to;
      const text = typeof data?.text === 'string' ? data.text.trim() : '';
      const imageUrl = typeof data?.imageUrl === 'string' ? data.imageUrl.trim() : '';

      if (!isValidObjectId(toUserId)) {
        return ack?.({ ok: false, error: 'Valid toUserId is required' });
      }
      if (!text && !imageUrl) {
        return ack?.({ ok: false, error: 'Message text or imageUrl is required' });
      }
      if (!isValidHttpUrl(imageUrl)) {
        return ack?.({ ok: false, error: 'Invalid imageUrl' });
      }

      const result = await createAndDispatchDm({
        senderUser: user,
        recipientId: toUserId,
        text,
        imageUrl,
      });
      if (result.error) {
        return ack?.({ ok: false, error: result.error });
      }
      return ack?.({ ok: true, message: result.message, clientTempId: data?.clientTempId || null });
    } catch (err) {
      console.error('[Socket send_dm]', err);
      return ack?.({ ok: false, error: 'Failed to send direct message' });
    }
  }

  socket.on('send_dm', handleSendDm);
  socket.on('private_message', handleSendDm);

  // Send Group Message (supports both "send_group_message" and "group_message")
  async function handleSendGroupMessage(data, ack) {
    try {
      const groupId = data?.groupId;
      const text = typeof data?.text === 'string' ? data.text.trim() : '';
      const imageUrl = typeof data?.imageUrl === 'string' ? data.imageUrl.trim() : '';

      if (!isValidObjectId(groupId)) {
        return ack?.({ ok: false, error: 'Valid groupId is required' });
      }
      if (!text && !imageUrl) {
        return ack?.({ ok: false, error: 'Message text or imageUrl is required' });
      }
      if (!isValidHttpUrl(imageUrl)) {
        return ack?.({ ok: false, error: 'Invalid imageUrl' });
      }

      const result = await createAndDispatchGroupMessage({
        senderUser: user,
        groupId,
        text,
        imageUrl,
      });
      if (result.error) {
        return ack?.({ ok: false, error: result.error });
      }
      return ack?.({ ok: true, message: result.message, clientTempId: data?.clientTempId || null });
    } catch (err) {
      console.error('[Socket send_group_message]', err);
      return ack?.({ ok: false, error: 'Failed to send group message' });
    }
  }

  socket.on('send_group_message', handleSendGroupMessage);
  socket.on('group_message', handleSendGroupMessage);

  // Mark messages read
  socket.on('mark_read', async (data, ack) => {
    try {
      const result = await markMessagesRead({
        userId: user._id,
        chatType: data?.chatType,
        peerId: data?.peerId,
        groupId: data?.groupId,
        messageIds: data?.messageIds,
      });
      if (result.error) return ack?.({ ok: false, error: result.error });
      return ack?.({ ok: true, ...result });
    } catch (err) {
      console.error('[Socket mark_read]', err);
      return ack?.({ ok: false, error: 'Failed to mark messages read' });
    }
  });

  // Typing indicator
  socket.on('typing', async (data) => {
    const isTyping = Boolean(data?.isTyping);
    if (data?.chatType === 'dm' && isValidObjectId(data?.peerId)) {
      io.to(`user:${String(data.peerId)}`).emit('user_typing', {
        chatType: 'dm',
        userId,
        username: user.username,
        isTyping,
      });
    } else if (data?.chatType === 'group' && isValidObjectId(data?.groupId)) {
      const isMember = await Group.exists({ _id: data.groupId, 'members.user': user._id });
      if (isMember) {
        socket.to(`group:${String(data.groupId)}`).emit('user_typing', {
          chatType: 'group',
          groupId: String(data.groupId),
          userId,
          username: user.username,
          isTyping,
        });
      }
    }
  });

  // Join a group room explicitly (verifies membership in DB first)
  socket.on('join_group', async (data, ack) => {
    if (!isValidObjectId(data?.groupId)) {
      return ack?.({ ok: false, error: 'Invalid groupId' });
    }
    const isMember = await Group.exists({ _id: data.groupId, 'members.user': user._id });
    if (!isMember) {
      return ack?.({ ok: false, error: 'Not a member of this group' });
    }
    socket.join(`group:${String(data.groupId)}`);
    return ack?.({ ok: true, groupId: String(data.groupId) });
  });

  socket.on('disconnect', async () => {
    const remaining = removeUserSocket(userId, socket.id);
    if (remaining === 0) {
      const lastSeenAt = new Date();
      await User.updateOne(
        { _id: user._id },
        { $set: { isOnline: false, lastSeenAt } }
      ).catch(() => {});
      io.emit('user_status', { userId, isOnline: false, lastSeenAt });
    }
  });
});

// =============================================================================
// 14. START SERVER & GRACEFUL SHUTDOWN
// =============================================================================

async function start() {
  if (!MONGODB_URI) {
    console.error('[FATAL] MONGODB_URI environment variable is not set.');
    process.exit(1);
  }

  await mongoose.connect(MONGODB_URI, {
    serverSelectionTimeoutMS: 10000,
  });
  console.log('[DB] Connected to MongoDB Atlas');

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`[SERVER] Listening on port ${PORT} (${NODE_ENV})`);
  });
}

start().catch((err) => {
  console.error('[FATAL] Failed to start server:', err);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  console.log('[SERVER] SIGTERM received, shutting down cleanly...');
  httpServer.close(async () => {
    await mongoose.connection.close().catch(() => {});
    process.exit(0);
  });
});
