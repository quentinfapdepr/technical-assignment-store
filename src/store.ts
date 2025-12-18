import { JSONArray, JSONObject, JSONPrimitive, JSONValue } from "./json-types";

export type Permission = "r" | "w" | "rw" | "none";

export type StoreResult = Store | JSONPrimitive | undefined;

export type StoreValue =
  | JSONObject
  | JSONArray
  | StoreResult
  | (() => StoreResult);

export interface IStore {
  defaultPolicy: Permission;
  allowedToRead(key: string): boolean;
  allowedToWrite(key: string): boolean;
  read(path: string): StoreResult;
  write(path: string, value: StoreValue): StoreValue;
  writeEntries(entries: JSONObject): void;
  entries(): JSONObject;
}

// Stores permissions set by @Restrict decorator, keyed by class prototype
const permissionsMap = new WeakMap<object, Map<string, Permission>>();

function getPermissionForKey(instance: Store, key: string): Permission {
  const instancePermissions = permissionsMap.get(instance);
  if (instancePermissions?.has(key)) {
    return instancePermissions.get(key)!;
  }

  let prototype = Object.getPrototypeOf(instance);
  while (prototype) {
    const classPermissions = permissionsMap.get(prototype);
    if (classPermissions?.has(key)) {
      return classPermissions.get(key)!;
    }
    prototype = Object.getPrototypeOf(prototype);
  }

  return instance.defaultPolicy;
}

function isJSONObject(value: unknown): value is JSONObject {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Store)
  );
}

function convertToStoreValue(value: JSONValue): StoreValue {
  if (isJSONObject(value)) {
    const store = new Store();
    store.writeEntries(value);
    return store;
  }
  return value as StoreValue;
}

function resolveValue(value: unknown): StoreResult {
  if (typeof value === "function") {
    return value();
  }
  return value as StoreResult;
}

export function Restrict(permission: Permission = "none"): PropertyDecorator {
  return function (target: object, propertyKey: string | symbol) {
    const key = String(propertyKey);

    if (!permissionsMap.has(target)) {
      permissionsMap.set(target, new Map());
    }

    permissionsMap.get(target)!.set(key, permission);
  };
}

export class Store implements IStore {
  [key: string]: unknown;

  defaultPolicy: Permission = "rw";
  private dynamicValues = new Map<string, StoreValue>();

  allowedToRead(key: string): boolean {
    const permission = getPermissionForKey(this, key);
    return permission === "r" || permission === "rw";
  }

  allowedToWrite(key: string): boolean {
    const permission = getPermissionForKey(this, key);
    return permission === "w" || permission === "rw";
  }

  read(path: string): StoreResult {
    const [key, ...rest] = path.split(":");

    if (!this.allowedToRead(key)) {
      throw new Error(`Read access denied for key: ${key}`);
    }

    const rawValue = this.getRawValue(key);
    const value = resolveValue(rawValue);

    if (rest.length === 0) {
      return value;
    }

    if (value instanceof Store) {
      return value.read(rest.join(":"));
    }

    return undefined;
  }

  write(path: string, value: StoreValue): StoreValue {
    const [key, ...rest] = path.split(":");

    if (rest.length === 0) {
      if (!this.allowedToWrite(key)) {
        throw new Error(`Write access denied for key: ${key}`);
      }
      const storeValue = isJSONObject(value)
        ? convertToStoreValue(value as JSONObject)
        : value;
      this.setRawValue(key, storeValue);
      return storeValue;
    }

    if (!this.allowedToRead(key)) {
      throw new Error(`Read access denied for key: ${key}`);
    }

    let nestedStore = resolveValue(this.getRawValue(key));

    if (nestedStore instanceof Store) {
      return nestedStore.write(rest.join(":"), value);
    }

    if (!this.allowedToWrite(key)) {
      throw new Error(`Write access denied for key: ${key}`);
    }

    nestedStore = new Store();
    this.setRawValue(key, nestedStore);
    return nestedStore.write(rest.join(":"), value);
  }

  writeEntries(entries: JSONObject): void {
    for (const [key, value] of Object.entries(entries)) {
      this.write(key, convertToStoreValue(value));
    }
  }

  entries(): JSONObject {
    const result: JSONObject = {};
    const allKeys = this.getAllKeys();

    for (const key of allKeys) {
      if (this.allowedToRead(key)) {
        const value = resolveValue(this.getRawValue(key));
        if (value instanceof Store) {
          result[key] = value.entries();
        } else if (value !== undefined) {
          result[key] = value as JSONValue;
        }
      }
    }

    return result;
  }

  private getRawValue(key: string): StoreValue | undefined {
    if (key in this && key !== "dynamicValues" && key !== "defaultPolicy") {
      return this[key] as StoreValue;
    }
    return this.dynamicValues.get(key);
  }

  private setRawValue(key: string, value: StoreValue): void {
    if (key in this && key !== "dynamicValues" && key !== "defaultPolicy") {
      this[key] = value;
    } else {
      this.dynamicValues.set(key, value);
    }
  }

  private getAllKeys(): string[] {
    const classKeys = Object.keys(this).filter(
      (k) => k !== "dynamicValues" && k !== "defaultPolicy"
    );
    const dynamicKeys = Array.from(this.dynamicValues.keys());
    const uniqueKeys = new Set([...classKeys, ...dynamicKeys]);
    return Array.from(uniqueKeys);
  }
}
