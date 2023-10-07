import { Injectable,ForbiddenException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import { Msg, Jwt } from './interfaces/auth.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  async signUp(dto: AuthDto): Promise<Msg>{
    console.log(dto.password);
    const hashed = await bcrypt.hash(dto.password,12);
    try{
      await this.prisma.user.create({
        data:{
          email: dto.email,
          hashedPassword: hashed,
        },
      });
      return {
        message: 'ok',
      };
    } catch(error){
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('This email is already taken');
        }
      }
      throw error;
    }
  }
  async login(dto:AuthDto):Promise<Jwt>{
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('Email or password incorrect');
    const isValid = await bcrypt.compare(dto.password,user.hashedPassword);
    console.log(isValid);
    if (!isValid) {
      // エラーメッセージと関連するデータをログに出力
      console.log('Password Check Failed');
      console.log('User:', user);
      console.log('Input Password:', dto.password);
      console.log('User Password:', user.hashedPassword);
      throw new ForbiddenException('Email or password incorrect');
    }
    return this.generateJwt(user.id,user.email);
  }

  async generateJwt(userId:number,email:string) : Promise<Jwt>{
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');
    const token = await this.jwt.signAsync(payload,{
      expiresIn: '5m',
      secret: secret,
    });
    return {
      accessToken: token,
    };
  }
}
