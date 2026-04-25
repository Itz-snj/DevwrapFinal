/**
 * Project Phoenix — Rule Index
 * 
 * Aggregates all detection rule files into a single export.
 * New rule categories are added here.
 */

import sqlInjectionRules from './sqlInjection.js';
import bruteForceRules from './bruteForce.js';
import pathTraversalRules from './pathTraversal.js';
import xssRules from './xss.js';
import commandInjectionRules from './commandInjection.js';

export const allRules = [
  ...sqlInjectionRules,
  ...bruteForceRules,
  ...pathTraversalRules,
  ...xssRules,
  ...commandInjectionRules
];

export {
  sqlInjectionRules,
  bruteForceRules,
  pathTraversalRules,
  xssRules,
  commandInjectionRules
};
