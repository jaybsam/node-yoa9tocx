const express = require('express');
const bcrypt = require('bcryptjs');
const joi = require('joi');
const cors = require('cors');
const app = express();
const port = 3000;

app.use(express.json());
const corsOptions = {
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));

import { Request, Response } from 'express';

interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// CODE HERE
//
// I want to be able to register a new unique user (username and password). After the user is created I
// should be able to login with my username and password. If a user register request is invalid a 400 error
// should be returned, if the user is already registered a conflict error should be returned.
// On login the users crendentials should be verified.
// Because we dont have a database in this environment we store the users in memory. Fill the helper functions
// to query the memory db.

function getUserByUsername(name: string): UserEntry | undefined {
  return Object.values(MEMORY_DB).find((user) => user.email === name);
}

function getUserByEmail(email: string): UserEntry | undefined {
  return MEMORY_DB[email];
}

const userSchema = joi.object({
  username: joi.string().min(3).max(24).required(),
  email: joi.string().email().required(),
  type: joi.string().valid('user', 'admin').required(),
  password: joi
    .string()
    .min(5)
    .max(24)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).*$/)
    .required(),
});

app.get('/', (req: Request, res: Response) => {
  const users = Object.keys(MEMORY_DB).map((username) => ({
    username,
    email: MEMORY_DB[username].email,
    type: MEMORY_DB[username].type,
  }));

  res.json(users);
});

// Request body -> UserDto
app.post('/register', async (req: Request, res: Response) => {
  // Validate user object using joi
  // - username (required, min 3, max 24 characters)
  // - email (required, valid email address)
  // - type (required, select dropdown with either 'user' or 'admin')
  // - password (required, min 5, max 24 characters, upper and lower case, at least one special character)
  const { username, email, type, password } = req.body;

  const { error } = userSchema.validate({ username, email, type, password });
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }
  if (getUserByUsername(username) || getUserByEmail(email)) {
    return res.status(409).json({ message: 'User already exists!' });
  }

  const salt = await bcrypt.genSalt(10);
  const passwordhash = await bcrypt.hash(password, salt);

  MEMORY_DB[email] = { email, type, salt, passwordhash };
  console.log('Users:', MEMORY_DB);

  res.status(201).json({ message: 'User registered successfully!' });
});

app.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  const user = getUserByUsername(username);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const isMatch = await bcrypt.compare(password, user.passwordhash);
  if (!isMatch) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  res.status(200).json({ message: 'Login successful' });
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
