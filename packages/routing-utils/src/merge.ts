import { Route, MergeRoutesProps, Build } from './types';
import { isHandler, HandleValue } from './index';

type BuilderToRoute = Map<string, Route[]>;

type BuilderRoutes = Map<string, BuilderToRoute>;

function getBuilderRoutesMapping(builds: Build[]): BuilderRoutes {
  const builderRoutes: BuilderRoutes = new Map();
  for (const { entrypoint, routes, use } of builds) {
    if (routes) {
      if (!builderRoutes.has(entrypoint)) {
        builderRoutes.set(entrypoint, new Map());
      }
      builderRoutes.get(entrypoint)!.set(use, routes);
    }
  }
  return builderRoutes;
}

function getCheckAndContinue(routes: Route[]): {
  checks: Route[];
  continues: Route[];
  others: Route[];
} {
  const checks: Route[] = [];
  const continues: Route[] = [];
  const others: Route[] = [];

  for (const route of routes) {
    if (isHandler(route)) {
      // Should never happen, only here to make TS happy
      throw new Error(
        `Unexpected route found in getCheckAndContinue(): ${JSON.stringify(
          route
        )}`
      );
    } else if (route.check && !route.override) {
      checks.push(route);
    } else if (route.continue && !route.override) {
      continues.push(route);
    } else {
      others.push(route);
    }
  }
  return { checks, continues, others };
}

export function mergeRoutes({ userRoutes, builds }: MergeRoutesProps): Route[] {
  const userHandleMap = new Map<HandleValue | null, Route[]>();
  let userPrevHandle: HandleValue | null = null;
  (userRoutes || []).forEach(route => {
    if (isHandler(route)) {
      userPrevHandle = route.handle;
    } else {
      const routes = userHandleMap.get(userPrevHandle);
      if (!routes) {
        userHandleMap.set(userPrevHandle, [route]);
      } else {
        routes.push(route);
      }
    }
  });

  const builderHandleMap = new Map<HandleValue | null, Route[]>();
  const builderRoutes = getBuilderRoutesMapping(builds);
  const sortedPaths = Array.from(builderRoutes.keys()).sort();
  sortedPaths.forEach(path => {
    const br = builderRoutes.get(path)!;
    const sortedBuilders = Array.from(br.keys()).sort();
    sortedBuilders.forEach(use => {
      let builderPrevHandle: HandleValue | null = null;
      br.get(use)!.forEach(route => {
        if (isHandler(route)) {
          builderPrevHandle = route.handle;
        } else {
          const routes = builderHandleMap.get(builderPrevHandle);
          if (!routes) {
            builderHandleMap.set(builderPrevHandle, [route]);
          } else {
            routes.push(route);
          }
        }
      });
    });
  });

  const outputRoutes: Route[] = [];
  const uniqueHandleValues = new Set([
    null,
    ...userHandleMap.keys(),
    ...builderHandleMap.keys(),
  ]);
  for (const handle of uniqueHandleValues) {
    const userRoutes = userHandleMap.get(handle) || [];
    const builderRoutes = builderHandleMap.get(handle) || [];
    const builderSorted = getCheckAndContinue(builderRoutes);
    if (
      handle !== null &&
      (userRoutes.length > 0 || builderRoutes.length > 0)
    ) {
      outputRoutes.push({ handle });
    }
    outputRoutes.push(...builderSorted.continues);
    outputRoutes.push(...userRoutes);
    outputRoutes.push(...builderSorted.checks);
    outputRoutes.push(...builderSorted.others);
  }
  return outputRoutes;
}
