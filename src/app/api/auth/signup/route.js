// app/api/auth/signup/route.js
import { NextResponse } from 'next/server';
import connectDB from '@/lib/mongodb';
import User from '@/models/User';
import { rateLimit } from '@/lib/rateLimiter';

export async function POST(request) {
  try {
    const ip = request.headers.get('x-real-ip') || request.headers.get('x-forwarded-for') || 'unknown';
    if (!rateLimit(ip)) {
      return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
    }

    const { name, email, password } = await request.json();

    if (!name || !email || !password) {
      return NextResponse.json({ error: 'All fields are required' }, { status: 400 });
    }
    if (password.length < 8) {
      return NextResponse.json({ error: 'Password must be at least 8 characters' }, { status: 400 });
    }

    await connectDB();

    const exists = await User.findOne({ email });
    if (exists) {
      return NextResponse.json({ error: 'User already exists' }, { status: 400 });
    }

    const user = await User.create({ name, email, password });

    // Optionally: send email verification here (not implemented)
    const payload = {
      id: user._id,
      email: user.email,
    };

    return NextResponse.json({
      message: 'User created successfully. Please verify your email before login.',
      user: { id: user._id, email: user.email, name: user.name, isVerified: user.isVerified }
    }, { status: 201 });
  } catch (err) {
    console.error('Signup error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
