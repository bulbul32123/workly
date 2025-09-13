// app/api/auth/me/route.js
import { NextResponse } from 'next/server';
import connectDB from '@/lib/mongodb';
import User from '@/models/User';
import { verifyAccessToken } from '@/lib/jwt';

export async function GET(request) {
  try {
    const access = request.cookies.get('accessToken')?.value;
    if (!access) return NextResponse.json({ user: null }, { status: 200 });

    const decoded = verifyAccessToken(access);
    if (!decoded) {
      return NextResponse.json({ user: null }, { status: 200 });
    }

    await connectDB();
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) return NextResponse.json({ user: null }, { status: 200 });

    return NextResponse.json({ user: { id: user._id, email: user.email, name: user.name, isVerified: user.isVerified } }, { status: 200 });
  } catch (err) {
    console.error('Me error:', err);
    return NextResponse.json({ user: null }, { status: 200 });
  }
}
