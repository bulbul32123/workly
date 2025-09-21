import { NextResponse } from 'next/server';
import connectDB from '@/lib/mongodb';
import User from '@/models/User';
import RefreshToken from '@/models/RefreshToken';
import { signAccessToken, signRefreshToken } from '@/lib/jwt';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { rateLimit } from '@/lib/rateLimiter';

const REFRESH_EXPIRE_SECONDS = 7 * 24 * 60 * 60; 

export async function POST(request) {
  try {
    const ip = request.headers.get('x-real-ip') || request.headers.get('x-forwarded-for') || 'unknown';
    if (!rateLimit(ip)) {
      return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
    }

    const { email, password } = await request.json();
    if (!email || !password) {
      return NextResponse.json({ error: 'Email and password are required' }, { status: 400 });
    }

    await connectDB();

    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    }

    const isValid = await user.comparePassword(password);
    if (!isValid) {
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    }


    const accessToken = signAccessToken({ userId: user._id, tokenVersion: user.tokenVersion });
    const refreshPlain = crypto.randomBytes(64).toString('hex');
    const refreshHash = await bcrypt.hash(refreshPlain, 12);
    const expiresAt = new Date(Date.now() + REFRESH_EXPIRE_SECONDS * 1000);

    await RefreshToken.create({ userId: user._id, tokenHash: refreshHash, expiresAt });

    const res = NextResponse.json({
      message: 'Login successful',
      user: { id: user._id, email: user.email, name: user.name, isVerified: user.isVerified }
    }, { status: 200 });
    const secure = process.env.NODE_ENV === 'production';
    res.cookies.set('accessToken', accessToken, {
      httpOnly: true,
      secure,
      sameSite: 'strict',
      maxAge: 15 * 60, 
      path: '/'
    });

    res.cookies.set('refreshToken', refreshPlain, {
      httpOnly: true,
      secure,
      sameSite: 'strict',
      maxAge: REFRESH_EXPIRE_SECONDS,
      path: '/'
    });

    return res;
  } catch (err) {
    console.error('Login error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
