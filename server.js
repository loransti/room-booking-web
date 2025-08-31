const express = require('express');
const mongoose = require('mongoose');
const moment = require('moment-timezone');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const expressLayouts = require('express-ejs-layouts');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'; // Change this!
const TIMEZONE = process.env.TIMEZONE || 'Europe/Berlin';
const BOT_TOKEN = process.env.BOT_TOKEN || process.env.TELEGRAM_BOT_TOKEN;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL; // e.g., https://room.example.com
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : undefined;
const SMTP_SECURE = process.env.SMTP_SECURE === 'true' || false;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const FROM_EMAIL = process.env.FROM_EMAIL || 'no-reply@example.com';
const NOTIFY_EMAILS = (process.env.NOTIFY_EMAILS || '').split(',').map(s => s.trim()).filter(Boolean);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');
// Expose path and default title to views for active nav and titles
app.use((req, res, next) => {
  res.locals.path = req.path;
  res.locals.title = '';
  next();
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Connect to MongoDB (same database as Telegram bot)
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Database Models (same as Telegram bot)
const userSchema = new mongoose.Schema({
  tg_id: { type: Number, required: true, unique: true },
  name: String,
  username: String,
  role: { type: String, enum: ['resident', 'admin'], default: 'resident' }
});

const stateSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  value: String
});

const bookingSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  user_tg: { type: Number },
  start: { type: Date, required: true },
  end: { type: Date, required: true },
  opener: {
    type: { type: String, enum: ['sod', 'keyb'] },
    tg_id: Number
  },
  opened_at: Date,
  closed_at: Date,
  status: { 
    type: String, 
    enum: ['confirmed', 'active', 'completed', 'overdue', 'cancelled'], 
    default: 'confirmed' 
  },
  created_at: { type: Date, default: Date.now }
});

const auditSchema = new mongoose.Schema({
  type: { type: String, required: true }, // e.g., 'opener_change'
  role: String, // 'sod' | 'keyb'
  actor_tg: Number,
  old_tg: Number,
  new_tg: Number,
  source: { type: String, default: 'web' },
  created_at: { type: Date, default: Date.now }
});

const requestSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  room: { type: String, required: true },
  tg_username: String,
  email: String,
  phone: String,
  start: { type: Date, required: true },
  end: { type: Date, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'cancelled'], default: 'pending' },
  email_token: String,
  email_confirmed_at: Date,
  created_booking_id: String,
  created_at: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const State = mongoose.model('State', stateSchema);
const Booking = mongoose.model('Booking', bookingSchema);
const Request = mongoose.model('Request', requestSchema);
const Audit = mongoose.model('Audit', auditSchema);

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session.authenticated) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Utility functions
const formatDateTime = (date) => {
  return moment(date).tz(TIMEZONE).format('DD.MM.YYYY HH:mm');
};

const getTimeSlots = () => {
  const slots = [];
  for (let hour = 8; hour <= 20; hour += 2) {
    const start = `${hour.toString().padStart(2, '0')}:00`;
    const end = `${(hour + 2).toString().padStart(2, '0')}:00`;
    slots.push({ start: hour, display: `${start}-${end}` });
  }
  return slots;
};

// Telegram notifications
const sendTelegramMessage = async (chatId, text) => {
  try {
    if (!BOT_TOKEN || !chatId) {
      console.warn('BOT_TOKEN not configured; skipping Telegram notification');
      return;
    }
    const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text })
    });
    if (!res.ok) {
      const errTxt = await res.text();
      console.error('Telegram send failed:', errTxt);
    }
  } catch (e) {
    console.error('Error sending Telegram message:', e);
  }
};

const sendTelegramMessageWithKeyboard = async (chatId, text, keyboard) => {
  try {
    if (!BOT_TOKEN) return;
    const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, reply_markup: keyboard ? { inline_keyboard: keyboard } : undefined })
    });
    if (!res.ok) {
      const errTxt = await res.text();
      console.error('Telegram send failed:', errTxt);
    }
  } catch (e) {
    console.error('Error sending Telegram message with keyboard:', e);
  }
};

const generateRequestId = () => 'RQ' + Date.now().toString().slice(-8);

// Email setup
let mailer = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT || 587,
    secure: SMTP_SECURE, // true for 465, false for 587/25
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
}

const getBaseUrl = (req) => {
  if (PUBLIC_BASE_URL) return PUBLIC_BASE_URL.replace(/\/$/, '');
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0];
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}`;
};

const sendEmail = async ({ to, subject, text, html }) => {
  if (!mailer) {
    console.warn('SMTP not configured; skipping email to', to);
    return;
  }
  await mailer.sendMail({ from: FROM_EMAIL, to, subject, text, html });
};

// Public booking form (no auth)
app.get('/book', async (req, res) => {
  const selectedDate = req.query.date || moment().tz(TIMEZONE).format('YYYY-MM-DD');
  const timeSlots = getTimeSlots();
  res.render('public_book', { layout: false, selectedDate, timeSlots, errors: null, old: {}, successId: null });
});

app.post('/book', async (req, res) => {
  try {
    const { name, room, tg_username, email, phone, date, slot } = req.body;
    const errors = [];
    const timeSlots = getTimeSlots();

    if (!name || name.trim().length < 2) errors.push('Please enter your full name.');
    if (!room || room.trim().length < 1) errors.push('Please enter your room number.');
    const emailVal = (email || '').trim();
    const phoneVal = (phone || '').trim();
    if (!emailVal && !phoneVal) {
      errors.push('Please provide an email or phone number.');
    }
    if (emailVal && !/^\S+@\S+\.[\w\-]{2,}$/.test(emailVal)) {
      errors.push('Please enter a valid email address.');
    }
    if (phoneVal && !/^[+]?[- 0-9()]{7,20}$/.test(phoneVal)) {
      errors.push('Please enter a valid phone number.');
    }
    if (!date) errors.push('Please select a date.');
    const startHour = parseInt(slot, 10);
    if (Number.isNaN(startHour)) errors.push('Please select a time slot.');

    const selectedDate = date || moment().tz(TIMEZONE).format('YYYY-MM-DD');
    let start = null, end = null;
    if (date && !Number.isNaN(startHour)) {
      const m = moment.tz(`${date} ${String(startHour).padStart(2, '0')}:00`, 'YYYY-MM-DD HH:mm', TIMEZONE);
      start = m.toDate();
      end = m.clone().add(2, 'hours').toDate();
      if (m.isBefore(moment().tz(TIMEZONE).add(30, 'minutes'))) {
        errors.push('Please choose a future time slot (at least 30 minutes from now).');
      }
    }

    if (errors.length) {
      return res.status(400).render('public_book', { layout: false, selectedDate, timeSlots, errors, old: req.body });
    }

    // Check conflicts with existing bookings
    const conflict = await Booking.findOne({
      status: { $in: ['confirmed', 'active'] },
      $or: [
        { start: { $lt: end }, end: { $gt: start } }
      ]
    });
    if (conflict) {
      return res.status(409).render('public_book', { layout: false, selectedDate, timeSlots, errors: ['Selected slot is already booked. Please choose another.'], old: req.body });
    }

    const reqId = generateRequestId();
    const token = crypto.randomBytes(24).toString('hex');
    const requestDoc = await Request.create({
      id: reqId,
      name: name.trim(),
      room: room.trim(),
      tg_username: tg_username ? tg_username.replace('@','').trim() : undefined,
      email: emailVal || undefined,
      phone: phoneVal || undefined,
      start,
      end,
      status: 'pending',
      email_token: token
    });

    // Notify SOD, Key-B, and Admins
    const [sodState, keybState, admins] = await Promise.all([
      State.findOne({ key: 'sod_tg' }),
      State.findOne({ key: 'keyb_tg' }),
      User.find({ role: 'admin' })
    ]);

    const when = `${formatDateTime(start)} - ${formatDateTime(end)}`;
    const contact = [
      requestDoc.tg_username ? `@${requestDoc.tg_username}` : null,
      requestDoc.email ? `📧 ${requestDoc.email}` : null,
      requestDoc.phone ? `📞 ${requestDoc.phone}` : null
    ].filter(Boolean).join(' · ');
    const who = `${requestDoc.name} (Room ${requestDoc.room})${contact ? `\n${contact}` : ''}`;
    const msg = `🆕 Booking request (pending)\n\n👤 ${who}\n📅 ${when}\n📋 Request: ${requestDoc.id}\n\nPlease confirm via email or in the admin panel.`;

    const keyboard = [
      // Buttons are for bot to handle if you add handlers later
      [
        { text: '✅ Approve', callback_data: `req_approve_${requestDoc.id}` },
        { text: '❌ Reject', callback_data: `req_reject_${requestDoc.id}` }
      ]
    ];

    const recipients = new Set();
    if (sodState && sodState.value) recipients.add(parseInt(sodState.value));
    if (keybState && keybState.value) recipients.add(parseInt(keybState.value));
    admins.forEach(a => a && a.tg_id && recipients.add(a.tg_id));
    for (const chatId of recipients) {
      await sendTelegramMessageWithKeyboard(chatId, msg, keyboard);
    }

    // Email requester with confirmation link
    if (requestDoc.email) {
      const base = getBaseUrl(req);
      const confirmUrl = `${base}/confirm-request?id=${encodeURIComponent(requestDoc.id)}&token=${encodeURIComponent(token)}`;
      const subject = `Confirm your booking request ${requestDoc.id}`;
      const html = `
        <p>Hello ${requestDoc.name},</p>
        <p>Please confirm your booking request:</p>
        <ul>
          <li>Date/Time: <strong>${when}</strong></li>
          <li>Room: <strong>${requestDoc.room}</strong></li>
          <li>Request ID: <strong>${requestDoc.id}</strong></li>
        </ul>
        <p><a href="${confirmUrl}">Click here to confirm</a></p>
        <p>If you didn't make this request, ignore this email.</p>
      `;
      const text = `Hello ${requestDoc.name},\n\nConfirm your booking request ${requestDoc.id}: ${confirmUrl}\nDate/Time: ${when}\nRoom: ${requestDoc.room}`;
      await sendEmail({ to: requestDoc.email, subject, text, html });
    }

    // Email copy to notify list (admins/opener emails, if configured)
    if (NOTIFY_EMAILS.length && requestDoc.email) {
      const base = getBaseUrl(req);
      const confirmUrl = `${base}/confirm-request?id=${encodeURIComponent(requestDoc.id)}&token=${encodeURIComponent(token)}`;
      const subject = `New booking request ${requestDoc.id}`;
      const html = `
        <p>New booking request pending confirmation:</p>
        <ul>
          <li>Name: ${requestDoc.name}</li>
          <li>Contact: ${[requestDoc.email ? '📧 '+requestDoc.email : null, requestDoc.phone ? '📞 '+requestDoc.phone : null].filter(Boolean).join(' · ')}</li>
          <li>Room: ${requestDoc.room}</li>
          <li>When: ${when}</li>
          <li>Request ID: ${requestDoc.id}</li>
        </ul>
        <p>Resident confirmation link: <a href="${confirmUrl}">${confirmUrl}</a></p>
      `;
      const text = `New booking request ${requestDoc.id}\nName: ${requestDoc.name}\nContact: ${[requestDoc.email, requestDoc.phone].filter(Boolean).join(' / ')}\nRoom: ${requestDoc.room}\nWhen: ${when}\nConfirm link: ${confirmUrl}`;
      await sendEmail({ to: NOTIFY_EMAILS.join(','), subject, text, html });
    }

    res.render('public_book', { layout: false, selectedDate, timeSlots, errors: null, old: {}, successId: requestDoc.id });
  } catch (error) {
    console.error('Public booking error:', error);
    res.status(500).send('Server error');
  }
});

// Email confirmation endpoint
app.get('/confirm-request', async (req, res) => {
  try {
    const { id, token } = req.query;
    if (!id || !token) return res.status(400).render('public_confirm', { ok: false, message: 'Invalid confirmation link.', details: null, layout: false });
    const requestDoc = await Request.findOne({ id });
    if (!requestDoc || !requestDoc.email_token) return res.status(404).render('public_confirm', { ok: false, message: 'Request not found or already processed.', details: null, layout: false });
    if (requestDoc.email_token !== token) return res.status(400).render('public_confirm', { ok: false, message: 'Invalid confirmation token.', details: null, layout: false });

    // Check for conflicts again at confirmation time
    const conflict = await Booking.findOne({
      status: { $in: ['confirmed', 'active'] },
      $or: [ { start: { $lt: requestDoc.end }, end: { $gt: requestDoc.start } } ]
    });
    if (conflict) {
      return res.status(409).render('public_confirm', { ok: false, message: 'Sorry, that time was just booked by someone else. Please choose another slot.', details: null, layout: false });
    }

    // Determine opener
    const sodState = await State.findOne({ key: 'sod_tg' });
    const keybState = await State.findOne({ key: 'keyb_tg' });
    let opener = null;
    if (sodState && sodState.value) opener = { type: 'sod', tg_id: parseInt(sodState.value) };
    else if (keybState && keybState.value) opener = { type: 'keyb', tg_id: parseInt(keybState.value) };

    // Create booking without Telegram user
    const bookingId = 'BK' + Date.now().toString().slice(-8);
    const booking = await Booking.create({
      id: bookingId,
      user_tg: undefined,
      start: requestDoc.start,
      end: requestDoc.end,
      opener,
      status: 'confirmed'
    });

    requestDoc.status = 'approved';
    requestDoc.email_confirmed_at = new Date();
    requestDoc.created_booking_id = booking.id;
    requestDoc.email_token = undefined;
    await requestDoc.save();

    const when = `${formatDateTime(booking.start)} - ${formatDateTime(booking.end)}`;

    // Email resident confirmation
    if (requestDoc.email) {
      const subject = `Your booking is confirmed ${booking.id}`;
      const html = `
        <p>Hello ${requestDoc.name},</p>
        <p>Your booking is confirmed.</p>
        <ul>
          <li>When: <strong>${when}</strong></li>
          <li>Room: <strong>${requestDoc.room}</strong></li>
          <li>Booking ID: <strong>${booking.id}</strong></li>
        </ul>
        <p>Please be on time. If you need to cancel, reply to this email.</p>
      `;
      const text = `Your booking is confirmed.\nWhen: ${when}\nRoom: ${requestDoc.room}\nBooking ID: ${booking.id}`;
      await sendEmail({ to: requestDoc.email, subject, text, html });
    }

    // Notify opener/admins via Telegram and/or email
    const notifyText = `✅ Booking confirmed via email\n\n👤 ${requestDoc.name} (Room ${requestDoc.room})\n${[requestDoc.email ? '📧 '+requestDoc.email : null, requestDoc.phone ? '📞 '+requestDoc.phone : null].filter(Boolean).join('\n')}\n📅 ${when}\n📋 ${booking.id}`;
    if (opener && opener.tg_id) {
      sendTelegramMessage(opener.tg_id, notifyText).catch(() => {});
    }
    const admins = await User.find({ role: 'admin' });
    admins.forEach(a => a.tg_id && sendTelegramMessage(a.tg_id, notifyText));

    if (NOTIFY_EMAILS.length) {
      const subject = `Booking confirmed ${booking.id}`;
      const html = `<p>${notifyText.replace(/\n/g, '<br>')}</p>`;
      await sendEmail({ to: NOTIFY_EMAILS.join(','), subject, text: notifyText, html });
    }

    return res.render('public_confirm', { ok: true, message: 'Your booking is confirmed!', details: { when, bookingId: booking.id }, layout: false });
  } catch (error) {
    console.error('Confirm request error:', error);
    res.status(500).render('public_confirm', { ok: false, message: 'Server error while confirming.', details: null, layout: false });
  }
});

// Routes

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: req.query.error, layout: false });
});

app.post('/login', async (req, res) => {
  const { password } = req.body;
  
  if (password === ADMIN_PASSWORD) {
    req.session.authenticated = true;
    // Go directly to the admin dashboard
    res.redirect('/admin');
  } else {
    res.redirect('/login?error=Invalid password');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Public home -> booking request page
app.get('/', (req, res) => {
  return res.redirect('/book');
});

// Admin dashboard
app.get('/admin', requireAuth, async (req, res) => {
  try {
    // Get statistics
    const totalBookings = await Booking.countDocuments();
    const activeBookings = await Booking.countDocuments({ 
      status: { $in: ['confirmed', 'active'] } 
    });
    const totalUsers = await User.countDocuments();
    const overdueBookings = await Booking.countDocuments({ status: 'overdue' });

    // Get recent bookings
    const recentBookings = await Booking.find()
      .sort({ created_at: -1 })
      .limit(10)
      .populate('user_tg');

    // Get users for each booking
    const bookingsWithUsers = [];
    for (const booking of recentBookings) {
      const user = await User.findOne({ tg_id: booking.user_tg });
      bookingsWithUsers.push({
        ...booking.toObject(),
        user: user
      });
    }

    // Get current SOD and Key-B
    const sodState = await State.findOne({ key: 'sod_tg' });
    const keybState = await State.findOne({ key: 'keyb_tg' });
    
    let sodUser = null, keybUser = null;
    if (sodState) {
      sodUser = await User.findOne({ tg_id: parseInt(sodState.value) });
    }
    if (keybState) {
      keybUser = await User.findOne({ tg_id: parseInt(keybState.value) });
    }

    res.render('dashboard', {
      stats: { totalBookings, activeBookings, totalUsers, overdueBookings },
      recentBookings: bookingsWithUsers,
      sodUser,
      keybUser,
      formatDateTime
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).send('Server error');
  }
});

// Bookings management
app.get('/bookings', requireAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 20;
    const skip = (page - 1) * limit;
    
    const filter = {};
    if (req.query.status) {
      filter.status = req.query.status;
    }
    if (req.query.date) {
      const date = moment(req.query.date);
      filter.start = {
        $gte: date.startOf('day').toDate(),
        $lte: date.endOf('day').toDate()
      };
    }

    const bookings = await Booking.find(filter)
      .sort({ start: -1 })
      .skip(skip)
      .limit(limit);

    const bookingsWithUsers = [];
    for (const booking of bookings) {
      const user = await User.findOne({ tg_id: booking.user_tg });
      bookingsWithUsers.push({
        ...booking.toObject(),
        user: user
      });
    }

    const totalBookings = await Booking.countDocuments(filter);
    const totalPages = Math.ceil(totalBookings / limit);

    res.render('bookings', {
      bookings: bookingsWithUsers,
      currentPage: page,
      totalPages,
      formatDateTime,
      query: req.query
    });
  } catch (error) {
    console.error('Bookings error:', error);
    res.status(500).send('Server error');
  }
});

// Calendar view
app.get('/calendar', requireAuth, async (req, res) => {
  try {
    const selectedDate = req.query.date || moment().tz(TIMEZONE).format('YYYY-MM-DD');
    const date = moment.tz(selectedDate, TIMEZONE);
    
    // Get bookings for the selected date
    const bookings = await Booking.find({
      start: {
        $gte: date.startOf('day').toDate(),
        $lte: date.endOf('day').toDate()
      },
      status: { $ne: 'cancelled' }
    }).sort({ start: 1 });

    const bookingsWithUsers = [];
    for (const booking of bookings) {
      const user = await User.findOne({ tg_id: booking.user_tg });
      bookingsWithUsers.push({
        ...booking.toObject(),
        user: user
      });
    }

    const timeSlots = getTimeSlots();
    
    res.render('calendar', {
      selectedDate,
      bookings: bookingsWithUsers,
      timeSlots,
      formatDateTime,
      moment
    });
  } catch (error) {
    console.error('Calendar error:', error);
    res.status(500).send('Server error');
  }
});

// Users management
app.get('/users', requireAuth, async (req, res) => {
  try {
    const users = await User.find().sort({ name: 1 });
    const sodState = await State.findOne({ key: 'sod_tg' });
    const keybState = await State.findOne({ key: 'keyb_tg' });

    res.render('users', {
      users,
      sodTgId: sodState ? parseInt(sodState.value) : null,
      keybTgId: keybState ? parseInt(keybState.value) : null
    });
  } catch (error) {
    console.error('Users error:', error);
    res.status(500).send('Server error');
  }
});

// API endpoints for AJAX operations
app.post('/api/bookings/:id/cancel', requireAuth, async (req, res) => {
  try {
    const booking = await Booking.findOne({ id: req.params.id });
    if (!booking) {
      return res.json({ success: false, message: 'Booking not found' });
    }

    booking.status = 'cancelled';
    await booking.save();

    // Notify user on Telegram (non-blocking)
    const user = await User.findOne({ tg_id: booking.user_tg });
    const msg = `Your booking ${booking.id} on ${formatDateTime(booking.start)} - ${formatDateTime(booking.end)} has been cancelled by admin.`;
    sendTelegramMessage(booking.user_tg, msg).catch(() => {});

    res.json({ success: true, message: 'Booking cancelled successfully' });
  } catch (error) {
    res.json({ success: false, message: 'Error cancelling booking' });
  }
});

app.post('/api/bookings/:id/force-close', requireAuth, async (req, res) => {
  try {
    const booking = await Booking.findOne({ id: req.params.id });
    if (!booking) {
      return res.json({ success: false, message: 'Booking not found' });
    }

    booking.status = 'completed';
    booking.closed_at = new Date();
    await booking.save();

    // Notify user on Telegram (non-blocking)
    const msg = `Your booking ${booking.id} has been force closed at ${formatDateTime(booking.closed_at)}.`;
    sendTelegramMessage(booking.user_tg, msg).catch(() => {});

    res.json({ success: true, message: 'Booking force closed successfully' });
  } catch (error) {
    res.json({ success: false, message: 'Error force closing booking' });
  }
});

app.post('/api/set-opener', requireAuth, async (req, res) => {
  try {
    const { type, userId } = req.body;
    const key = type === 'sod' ? 'sod_tg' : 'keyb_tg';
    const newTgId = parseInt(userId);

    // Load previous holder
    const prev = await State.findOne({ key });
    const oldTgId = prev ? parseInt(prev.value) : null;

    // If no change, acknowledge and exit
    if (oldTgId === newTgId) {
      return res.json({ success: true, message: `${type.toUpperCase()} unchanged` });
    }

    // Update state
    await State.findOneAndUpdate(
      { key },
      { value: newTgId.toString() },
      { upsert: true }
    );

    // Notify new holder, previous holder, and admins (best effort)
    const [newUser, oldUser, admins] = await Promise.all([
      User.findOne({ tg_id: newTgId }),
      oldTgId ? User.findOne({ tg_id: oldTgId }) : null,
      User.find({ role: 'admin' })
    ]);

    const roleLabel = type.toUpperCase();
    const nowStr = formatDateTime(new Date());

    // New holder notification
    if (newTgId) {
      const msg = `✅ You are now the ${roleLabel} holder.\n\n` +
                  `• You may receive open/close requests for bookings.\n` +
                  `• Set by admin at ${nowStr}.`;
      sendTelegramMessage(newTgId, msg).catch(() => {});
    }

    // Old holder notification
    if (oldTgId && oldTgId !== newTgId) {
      const msg = `ℹ️ You are no longer the ${roleLabel} holder as of ${nowStr}.`;
      sendTelegramMessage(oldTgId, msg).catch(() => {});
    }

    // Admins notification
    const oldName = oldUser ? (oldUser.name || ('@' + (oldUser.username || oldTgId))) : 'None';
    const newName = newUser ? (newUser.name || ('@' + (newUser.username || newTgId))) : newTgId;
    const adminMsg = `🔔 ${roleLabel} changed\n\nFrom: ${oldName}\nTo: ${newName}\nAt: ${nowStr}\nSource: Web admin`;
    admins.forEach(a => {
      if (a && a.tg_id) sendTelegramMessage(a.tg_id, adminMsg).catch(() => {});
    });

    // Audit log
    await Audit.create({
      type: 'opener_change',
      role: type,
      actor_tg: null, // web session (unknown tg)
      old_tg: oldTgId || null,
      new_tg: newTgId,
      source: 'web'
    });

    res.json({ success: true, message: `${type.toUpperCase()} updated and notified` });
  } catch (error) {
    res.json({ success: false, message: 'Error updating opener' });
  }
});

// Export data
app.get('/api/export', requireAuth, async (req, res) => {
  try {
    const bookings = await Booking.find({}).sort({ created_at: -1 });
    
    let csv = 'ID,User,Start,End,Opener,Status,Created\n';
    
    for (const booking of bookings) {
      const user = await User.findOne({ tg_id: booking.user_tg });
      csv += `${booking.id},`;
      csv += `${user ? user.name : 'Unknown'},`;
      csv += `${formatDateTime(booking.start)},`;
      csv += `${formatDateTime(booking.end)},`;
      csv += `${booking.opener ? booking.opener.type : 'None'},`;
      csv += `${booking.status},`;
      csv += `${formatDateTime(booking.created_at)}\n`;
    }
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=bookings.csv');
    res.send(csv);
  } catch (error) {
    res.status(500).send('Error exporting data');
  }
});

// Start server
mongoose.connection.once('open', () => {
  console.log('Connected to MongoDB');
  app.listen(PORT, () => {
    console.log(`Web interface running on port ${PORT}`);
    console.log(`Access at: http://localhost:${PORT}`);
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});
