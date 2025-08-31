const express = require('express');
const mongoose = require('mongoose');
const moment = require('moment-timezone');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const expressLayouts = require('express-ejs-layouts');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'; // Change this!
const TIMEZONE = process.env.TIMEZONE || 'Europe/Berlin';
const BOT_TOKEN = process.env.BOT_TOKEN || process.env.TELEGRAM_BOT_TOKEN;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

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
  public_token: { type: String, unique: true },
  reservation_code: { type: String, index: true },
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
    if (!BOT_TOKEN) {
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
const generateToken = () => Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
const generateCode = () => Math.random().toString(36).slice(2, 8).toUpperCase();

// Public booking form (no auth)
app.get('/book', async (req, res) => {
  const selectedDate = req.query.date || moment().tz(TIMEZONE).format('YYYY-MM-DD');
  const timeSlots = getTimeSlots();
  res.render('public_book', { layout: false, selectedDate, timeSlots, errors: null, old: {}, successId: null, statusUrl: null, reservationCode: null });
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
    const token = generateToken();
    let code = generateCode();
    const exists = await Request.findOne({ reservation_code: code });
    if (exists) code = generateCode();
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
      public_token: token,
      reservation_code: code
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
    const msg = `🆕 Booking request (pending)\n\n👤 ${who}\n📅 ${when}\n📋 Request: ${requestDoc.id}\n\nPlease confirm in the admin panel.`;

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

    const statusUrl = `/r/${token}`;
    res.render('public_book', { layout: false, selectedDate, timeSlots, errors: null, old: {}, successId: requestDoc.id, statusUrl, reservationCode: code });
  } catch (error) {
    console.error('Public booking error:', error);
  res.status(500).send('Server error');
  }
});

// Status lookup by reservation code
app.get('/status', async (req, res) => {
  try {
    const code = (req.query.code || '').toUpperCase();
    if (code) {
      const r = await Request.findOne({ reservation_code: code });
      if (r && r.public_token) {
        return res.redirect(`/r/${r.public_token}`);
      }
    }
    return res.render('status_lookup', { layout: false });
  } catch (err) {
    console.error('Status lookup error:', err);
    return res.status(500).send('Server error');
  }
});

// Status page (magic link)
app.get('/r/:token', async (req, res) => {
  try {
    const token = req.params.token;
    const r = await Request.findOne({ public_token: token });
    if (!r) return res.status(404).send('Not found');
    return res.render('status', { layout: false, token });
  } catch (err) {
    console.error('Status page error:', err);
    return res.status(500).send('Server error');
  }
});

// Status JSON (polled by status page)
app.get('/api/status/:token', async (req, res) => {
  try {
    const token = req.params.token;
    const r = await Request.findOne({ public_token: token });
    if (!r) return res.json({ ok: false, error: 'not_found' });
    let booking = null;
    let openerUser = null;
    let residentUser = null;
    if (r.created_booking_id) {
      booking = await Booking.findOne({ id: r.created_booking_id });
      if (booking && booking.user_tg) {
        residentUser = await User.findOne({ tg_id: booking.user_tg });
      }
      if (booking && booking.opener && booking.opener.tg_id) {
        openerUser = await User.findOne({ tg_id: booking.opener.tg_id });
      }
    }
    return res.json({
      ok: true,
      request: {
        id: r.id,
        name: r.name,
        room: r.room,
        start: r.start,
        end: r.end,
        status: r.status,
        reservation_code: r.reservation_code
      },
      booking: booking ? {
        id: booking.id,
        status: booking.status,
        start: booking.start,
        end: booking.end,
        opener: booking.opener,
        opened_at: booking.opened_at,
        closed_at: booking.closed_at,
        opener_name: openerUser ? (openerUser.name || ('@' + (openerUser.username || openerUser.tg_id))) : null,
        resident_name: residentUser ? (residentUser.name || ('@' + (residentUser.username || residentUser.tg_id))) : null
      } : null
    });
  } catch (err) {
    console.error('Status JSON error:', err);
    return res.json({ ok: false, error: 'server_error' });
  }
});

// Public cancel via token
app.post('/api/status/:token/cancel', async (req, res) => {
  try {
    const token = req.params.token;
    const r = await Request.findOne({ public_token: token });
    if (!r) return res.json({ ok: false, error: 'not_found' });
    if (r.created_booking_id) {
      const booking = await Booking.findOne({ id: r.created_booking_id });
      if (!booking) return res.json({ ok: false, error: 'booking_not_found' });
      booking.status = 'cancelled';
      await booking.save();
    }
    r.status = 'cancelled';
    await r.save();
    return res.json({ ok: true });
  } catch (err) {
    console.error('Cancel via token error:', err);
    return res.json({ ok: false, error: 'server_error' });
  }
});
// Webhook: called by the bot after approval to keep status in sync (no email)
app.post('/api/request-approved', async (req, res) => {
  try {
    const sig = req.get('x-webhook-secret');
    if (!WEBHOOK_SECRET || sig !== WEBHOOK_SECRET) {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    const { requestId, bookingId } = req.body || {};
    if (!requestId) return res.status(400).json({ ok: false, error: 'missing requestId' });

    const requestDoc = await Request.findOne({ id: requestId });
    if (!requestDoc) return res.status(404).json({ ok: false, error: 'request_not_found' });

    // If booking id missing, create booking with no telegram user
    let finalBookingId = bookingId;
    if (!finalBookingId) {
      const gen = 'BK' + Date.now().toString().slice(-8);
      const sodState = await State.findOne({ key: 'sod_tg' });
      const keybState = await State.findOne({ key: 'keyb_tg' });
      let opener = null;
      if (sodState && sodState.value) opener = { type: 'sod', tg_id: parseInt(sodState.value) };
      else if (keybState && keybState.value) opener = { type: 'keyb', tg_id: parseInt(keybState.value) };
      await Booking.create({ id: gen, start: requestDoc.start, end: requestDoc.end, opener, status: 'confirmed' });
      finalBookingId = gen;
    }

    requestDoc.status = 'approved';
    requestDoc.created_booking_id = finalBookingId;
    await requestDoc.save();
    return res.json({ ok: true, bookingId: finalBookingId });
  } catch (err) {
    console.error('request-approved webhook error:', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
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
