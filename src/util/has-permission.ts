import { Permission } from "../enum";

export const isAdmin = (permission: Permission | string): boolean => permission === Permission.ADMIN;

export const isUser = (permission: Permission | string): boolean => permission === Permission.USER;

export const isLocked = (permission: Permission | string): boolean => permission === Permission.LOCKED;
