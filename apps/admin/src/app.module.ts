import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { config } from './config.js';

@Module({
  imports: [ConfigModule.forRoot(config)],
})
export class AppModule {}
