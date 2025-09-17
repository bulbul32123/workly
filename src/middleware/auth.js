import { NextResponse } from 'next/server';
import connectDB from '@/lib/mongodb';
import User from '@/models/User';

export async function getAuthUser(request) {
    try {
        const token = request.cookies.get('token')?.value;

        if (!token) {
            return null;
        }

        const decoded = verifyToken(token);
        if (!decoded) {
            return null;
        }

        await connectDB();
        const user = await User.findById(decoded.userId).select('-password');
        return user;
    } catch (error) {
        return null;
    }
}

export function withAuth(handler) {
    return async (request, context) => {
        const user = await getAuthUser(request);

        if (!user) {
            return NextResponse.json(
                { error: 'Authentication required' },
                { status: 401 }
            );
        }

        request.user = user;
        return handler(request, context);
    };
}