// import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import httpStatus from 'http-status';
import AppError from '../../errors/AppError';
import { User } from '../user/user.model';
import { TLoginUser } from './auth.interface';
import config from '../../config';

const loginUser = async (payload: TLoginUser) => {
  // checking if the user exist---------
  const user = await User.isUserExistsByCustomId(payload.id);
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found!');
  }

  //  checking if the user is already deleted----------
  const isDeleted = user?.isDeleted;
  //   console.log('deleted //', isDeleted);
  if (isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted!');
  }

  //  checking if the user is blocked----------
  const userStatus = user?.status;
  //   console.log('status //', userStatus);
  if (userStatus === 'blocked') {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked!');
  }

  // checking if the password correct
  if (!(await User.isPasswordMatched(payload?.password, user?.password))) {
    throw new AppError(httpStatus.FORBIDDEN, 'Password dost match!');
  }

  // Access Granted: Send AccessToken, RefreshToken
  // create token
  const jwtPayload = {
    userId: user,
    role: user.role,
  };
  const accessToken = jwt.sign(jwtPayload, config.jwt_access_secret as string, {
    expiresIn: '10d',
  });

  return { accessToken, needsPasswordChange: user?.needsPasswordChange };
};
export const AuthService = {
  loginUser,
};
