(ns com.latacora.replik8s.query-utils
  (:require
   [clojure.data.json :as json]
   [clojure.java.io :as io]
   [clojure.string]
   [com.latacora.replik8s.datascript :refer [make-db]]
   [com.latacora.replik8s.utils]
   [com.rpl.specter :as specter]))

(defn sanitize-keyword [kw]
  (let [kw-str (name kw)]                                   ;; Convert the keyword to a string
    (-> kw-str
        (clojure.string/replace #"[^\w-]" "_")              ;; Replace any non-word character with an underscore
        (clojure.string/replace #"^_+" "")                  ;; Remove any leading underscores
        (clojure.string/replace #"__" "_")                  ;; Replace any double underscores with a single underscore
        keyword)))

(defn stringify-keys
  "Convert data to strings to allow including them in query responses."
  [data]
  (let [transformations #{:rules}]
    (specter/transform
     [(specter/walker #(and (map? %) (some (fn [key] (contains? % key)) transformations)))]
     (fn [d]
       (reduce
        (fn [updated-map key]
          (if (contains? updated-map key)
              ;; the map has the key, process
            (let [original-val (get updated-map key)]
              (merge updated-map
                       ;; convert original value to a string
                     {(keyword (namespace key) (str (name key) ".string"))
                      (str original-val)}))
              ;; the map doesn't have the key, so it is further into the map, process recursively
            (stringify-keys updated-map)))
        d
        transformations))
     data)))

(defn load-snapshot
  "Load a single snapshot as a map."
  [path]
  (->
   (json/read-str (slurp path) :key-fn sanitize-keyword)
   stringify-keys))

(defn directory->db
  "Load a directory of snapshots into a DB."
  ([]
   (directory->db "snapshots"))
  ([directory]
   (let [snapshot-files (->> (io/file directory)
                             (.listFiles)
                             (map #(.getName %))
                             (filter #(clojure.string/starts-with? % "replik8s-snapshot-"))
                             (map #(str directory "/" %)))
         snapshots      (into {}
                              (pmap (fn [snapshot]
                                      [snapshot (load-snapshot snapshot)])
                                    snapshot-files))]
     (make-db snapshots))))
