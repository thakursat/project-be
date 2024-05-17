const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();
const app = express();
app.use(express.json());
const multer = require('multer')
const cors = require('cors')
var bodyParser = require('body-parser')


app.use(bodyParser.urlencoded({ extended: false }))

app.use(cors('*'))

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    return cb(null, './uploads');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const extension = path.extname(file.originalname);
    return cb(null, file.fieldname + '-' + uniqueSuffix + extension);
  }
});

const upload = multer({ storage: storage });

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

const extractUserId = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ error: 'Authorization header missing' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  profileImage: String,
});

const User = mongoose.model('User', userSchema);

app.post('/signup', upload.single('file'), async (req, res) => {
  try {
    const { username, password, email } = req.body;
    const profileImage = req.file ? `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}` : null;


    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    if (!email.match(/^\S+@\S+\.\S+$/)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, username, password: hashedPassword, profileImage });

    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

    res.status(201).json({ token });
  } catch (error) {
    console.error('Error signing up:', error);
    res.status(500).send('Error signing up');
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).send('Invalid username or password');
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).send('Invalid username or password');
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.status(200).json({ token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).send('Error logging in');
  }
});

app.post('/upload', extractUserId, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).send('No file uploaded');
    }
    profileImage = req.file.path
    const userId = req.userId;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send('User not found');
    }
    user.profileImage = `${req.protocol}://${req.get('host')}/${req.file.filename}`;
    await user.save();
    res.status(200).json({ profileImage });
    console.log(req.file)
  } catch (error) {
    console.error('Error uploading file:', error);
    res.status(500).send('Error uploading file');
  }
});

app.get('/', extractUserId, async (req, res) => {
  try {
    const userId = req.userId;
    console.log("userdata:", userId);
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send('User not found');
    }

    const userProfile = {
      username: user.username,
      email: user.email,
      profileImage: user.profileImage
    };

    res.status(200).json(userProfile);
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).send('Error fetching user profile');
  }
});



const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
