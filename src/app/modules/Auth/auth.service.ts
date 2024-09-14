import httpStatus from 'http-status';
import AppError from '../../errors/AppError';
import { User } from '../user/user.model';
import { TLoginUser } from './auth.interface';

const loginUser = async (payload: TLoginUser) => {
  // checking if the user exist---------
  const isUserExists = await User.findOne({ id: payload?.id });
  //   console.log(isUserExists);
  if (!isUserExists) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found!');
  }

  //  checking if the user is already deleted----------
  const isDeleted = await isUserExists.isDeleted;
  console.log(isUserExists);
  if (isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted!');
  }

  console.log(payload);
  return {};
};

export const AuthService = {
  loginUser,
};
