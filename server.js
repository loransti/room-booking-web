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
  user_tg: { type: Number, required: true },
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

const User = mongoose.model('User', userSchema);
const State = mongoose.model('State', stateSchema);
const Booking = mongoose.model('Booking', bookingSchema);

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

// Routes

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: req.query.error, layout: false });
});

app.post('/login', async (req, res) => {
  const { password } = req.body;
  
  if (password === ADMIN_PASSWORD) {
    req.session.authenticated = true;
    res.redirect('/');
  } else {
    res.redirect('/login?error=Invalid password');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Dashboard
app.get('/', requireAuth, async (req, res) => {
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

    res.json({ success: true, message: 'Booking force closed successfully' });
  } catch (error) {
    res.json({ success: false, message: 'Error force closing booking' });
  }
});

app.post('/api/set-opener', requireAuth, async (req, res) => {
  try {
    const { type, userId } = req.body;
    const key = type === 'sod' ? 'sod_tg' : 'keyb_tg';
    
    await State.findOneAndUpdate(
      { key },
      { value: userId.toString() },
      { upsert: true }
    );

    res.json({ success: true, message: `${type.toUpperCase()} updated successfully` });
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
