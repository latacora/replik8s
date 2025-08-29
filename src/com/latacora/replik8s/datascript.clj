(ns com.latacora.replik8s.datascript
  (:require
   [clojure.string :as str]
   [com.latacora.replik8s.utils]
   [taoensso.timbre :refer [warnf]]))

(defn incrementing
  "Creates a (stateful) function that successively returns 1, 2, 3, ..."
  []
  (let [n (atom 0)]
    (fn [] (swap! n inc))))

(defn ->kw
  "Convert a number of arguments into keywords for datascript.

  (->kw :a) => :a
  (->kw :a :b) => :a/b
  (->kw :a/b) => :a/b
  (->kw \"a\") => :a
  (->kw \"a\" \"b\") => :a/b"
  [& args]
  (let [->str
        (fn [x]
          (cond
            (string? x)
            x
            (qualified-keyword? x)
            (str (namespace x) "/" (name x))
            (keyword? x)
            (name x)
            :else
            (do
              (warnf "Encountered something we don't know to stringify in ->kw: %s" x)
              (pr-str x))))]
    (->> args
         (map ->str)
         (str/join ".")
         (keyword))))

(defn expand
  "Convert a nested datastructure into a sequence of EAV triples for datascript, optionally
  given a function that generates eids."
  ([m]
   (expand m {:next-id  (incrementing)
              :->kw     (memoize ->kw)}))
  ([m {:keys [next-id id ->kw] :as opts}]
   (if-not (map? m)
     (throw (Exception. "Direct argument to datascript/expand must be a map!"))
     ;; We could use :pr {id (next-id)}, but that makes extra calls to (next-id) when you supply
     ;; the :id. This way we get consecutive numbers and never call (next-id) unless we're going
     ;; to use it.
     (let [id (or id (next-id))]
       (mapcat
        (fn [[k v]]
          (cond
             ;; Maps inside a map get expanded to a series of triples
             ;; representing their values at specific keys. Each value
             ;; gets expanded as well.
            (map? v)
            (let [here (next-id)]
              (lazy-cat
               [[id  (->kw k) here]]
               (expand v (assoc opts :id here :next-id next-id))))
             ;; Vectors inside maps get expanded to a series of triples
             ;; representing each of their contained items. Items get
             ;; expanded if they're maps or vectors; otherwise they get
             ;; directly included.
             ;; We also add an :k.all so that we can directly get the
             ;; full vector.
            (vector? v)
            (apply
             concat
             [[id (->kw k "all") v]]
             (for [item v]
               (if (map? item)
                 (let [here (next-id)]
                   (lazy-cat
                    [[id (->kw k) here]]
                    (expand item (assoc opts :id here :next-id next-id))))
                 [[id (->kw k) item]])))
             ;; Non-map non-vector items get expanded directly to
             ;; their k
            :else
            [[id (->kw k) v]]))
        m)))))

(defn make-db
  [input]
  (let [options {:next-id  (incrementing)
                 :->kw     (memoize ->kw)}]
    (expand input options)))
