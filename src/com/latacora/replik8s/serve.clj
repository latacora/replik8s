(ns com.latacora.replik8s.serve
  (:gen-class)
  (:require
   [clojure.data.json :as json]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [com.latacora.replik8s.utils :as utils]
   [ring.adapter.jetty :refer [run-jetty]]
   [ring.middleware.gzip :refer [wrap-gzip]]
   [taoensso.timbre :as timbre])
  (:import (java.time LocalDateTime)))

;; Atom to hold the server instance
(defonce server (atom nil))

;; Atom to cache loaded snapshots
(defonce snapshot-cache (atom {}))

(defn filter-ns
  "Filters out resources by namespace, typical for namespaced resources in Kubernetes."
  [response namespace]
  (let [items (filter #(= (get-in % ["metadata" "namespace"]) namespace)
                      (get response "items" []))]
    (assoc response "items" items)))

(defn get-resource-by-name
  "Returns a single resource requested by name, typical for `kubectl describe` calls."
  [response name]
  (when (and response (contains? response "items"))
    (let [resource (first (filter #(= (get-in % ["metadata" "name"]) name)
                                  (get response "items" [])))]
      (when resource
        (-> resource
            (assoc "kind" (str/replace (get response "kind" "") "List" ""))
            (assoc "apiVersion" (get response "apiVersion")))))))

(defn load-snapshot
  "Loads a snapshot file based on the given timestamp and caches it."
  [snapshot-directory timestamp]
  (let [snapshot-path (if (= timestamp "latest")
                        (utils/datetime->snapshot snapshot-directory (LocalDateTime/now))
                        (utils/datetime->snapshot snapshot-directory (utils/date-str->datetime timestamp)))
        snapshot-path (str snapshot-directory "/" snapshot-path)
        _             (timbre/debugf "Loading snapshot at path %s" snapshot-path)]
    (if-let [cached-snapshot (@snapshot-cache snapshot-path)]
      cached-snapshot
      (let [snapshot (when (.exists (java.io.File. snapshot-path))
                       (json/read-str (slurp snapshot-path)))
            snapshot (get snapshot "resources")]
        (when snapshot
          (swap! snapshot-cache assoc snapshot-path snapshot))
        snapshot))))

(defn get-resource
  "Given an API path, return the correct resources."
  [snapshot-directory path]
  (let [_                 (timbre/debugf "Getting resource for %s" path)
        pattern-timestamp #"^/(\d{4}-\d{2}-\d{2}_\d{2}:\d{2})"
        [timestamp-path timestamp] (re-find pattern-timestamp path)
        data              (if timestamp
                            (do
                              (timbre/debugf "Using snapshot with timestamp %s" timestamp)
                              (load-snapshot snapshot-directory timestamp))
                            (do
                              (timbre/debugf "No timestamp, returning latest snapshot")
                              (load-snapshot snapshot-directory "latest")))
        path              (if timestamp-path
                            (str/replace path timestamp-path "")
                            path)
        response          (get data path)]
    (if response
      ;; response found directly in the snapshot
      response
      ;; look further
      (let [pattern-ns #"/namespaces/([^/]+)/"
            [ns-path ns] (re-find pattern-ns path)
            new-path   (if ns-path (str/replace path ns-path "/") path)
            response   (get data new-path)]
        (if response
          ;; filter out ns data if the path includes a ns
          (if ns
            (filter-ns response ns)
            response)
          ;; return a single item if the path ends with a resource name
          (let [pattern-name #".*(?=\/)"
                result-name  (re-find pattern-name new-path)
                name         (last (str/split new-path #"/"))
                new-path     (if result-name result-name new-path)
                response     (get data new-path)
                response-ns  (filter-ns response ns)]
            (if name
              (if ns
                (get-resource-by-name response-ns name)
                (get-resource-by-name response name))
              (timbre/warn (str "No data for path " path)))))))))

(defn create-handler
  [snapshot-directory]
  (-> (fn [request]
        (let [uri     (get request :uri)
              _       (timbre/debug (format "GET %s" uri))
              content (get-resource snapshot-directory uri)]
          (if content
            (do
              (timbre/infof "200 GET %s" uri)
              {:status  200
               :headers {"Content-Type" "application/json"}
               :body    (json/write-str content)})
            (do
              (timbre/warnf "404 GET %s" uri)
              {:status  404
               :headers {"Content-Type" "text/plain"}
               :body    (format "No data for URI %s" uri)}))))
      wrap-gzip))

(defn start-server
  "Start the server"
  ([]
   (start-server "snapshots"))
  ([snapshot-directory]
   (timbre/infof "Generating kubeconfig file for all snapshots in the \"%s\" directory" snapshot-directory)
   (utils/generate-kubeconfig-all-snapshots snapshot-directory "kubeconfig-all-snapshots.json")
   (timbre/infof "Serving %s" snapshot-directory)
   (let [handler      (create-handler snapshot-directory)
         ;; load from resources, copy to temp file so Jetty can read it
         ;; used when running from a jar
         keystore-url (io/resource "certificates/keystore.p12")
         temp-keystore (java.io.File/createTempFile "keystore" ".p12")
         _ (.deleteOnExit temp-keystore)
         _ (when keystore-url (io/copy (io/input-stream keystore-url) temp-keystore))
         keystore-temporary-path (.getAbsolutePath temp-keystore)]
     (when @server
       (timbre/info "Stopping existing server")
       (.stop @server))                                     ;; Stop the current server if running
     (timbre/info "Starting new server on ports 3000 (HTTP) and 3443 (HTTPS)")
     (reset! server
             (run-jetty handler
                        {:port            3000
                         :ssl?            true
                         :ssl-port        3443
                         :keystore        (if keystore-url
                                            ;; run from jar
                                            keystore-temporary-path
                                            ;; run from source
                                            "resources/certificates/keystore.p12")
                         :keystore-type   "PKCS12"
                         :key-password    ""
                         :join?           false
                         :sni-host-check? false})))))

(comment
  (start-server))
