import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { configAdmin } from './config.js';

@Module({
  imports: [ConfigModule.forRoot(configAdmin())],
})
export class AppModule {}
