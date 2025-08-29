(ns com.latacora.replik8s.utils
  (:gen-class)
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.data.json :as json]
            [taoensso.timbre :as timbre])
  (:import (java.time LocalDateTime)
           (java.time.format DateTimeFormatter)
           (java.util TimeZone)))

(defn date-str->datetime
  "Given a date string in YYYY-MM-DD_HH:MM format, return its datetime."
  [date-str]
  (try
    (LocalDateTime/parse date-str (DateTimeFormatter/ofPattern "yyyy-MM-dd_HH:mm"))
    (catch Exception _
      (timbre/error "Invalid date format. Using current date and time.")
      (LocalDateTime/now))))

(defn datetime->date-str
  "Converts a Unix timestamp (milliseconds) to an ISO 8601 string."
  [timestamp]
  (let [date   (java.util.Date. timestamp)
        format (java.text.SimpleDateFormat. "yyyy-MM-dd_HH:mmXXX")]
    (.setTimeZone format (TimeZone/getTimeZone "UTC"))
    (.format format date)))

(defn date-str->epoch
  "Converts an ISO 8601 string (yyyy-MM-dd_HH:mmZ) to a Unix timestamp (milliseconds)."
  [date-string]
  (let [format (java.text.SimpleDateFormat. "yyyy-MM-dd_HH:mm'Z'")]
    (.setTimeZone format (java.util.TimeZone/getTimeZone "UTC"))
    (.getTime (.parse format date-string))))

(defn snapshot->datetime
  "Given a snapshot file name, return its datetime."
  [filename]
  (try
    (let [formatter    (DateTimeFormatter/ofPattern "yyyy-MM-dd_HH:mm")
          datetime-str (-> filename
                           (str/split #"replik8s-snapshot-")
                           (last)
                           (str/replace #"\.json$" ""))]
      (java.time.LocalDateTime/parse datetime-str formatter))
    (catch Exception _ nil)))

(defn datetime->snapshot
  "Given a datetime, return the snapshot that's closest."
  ([target-datetime]
   (datetime->snapshot "snapshots" target-datetime))
  ([snapshot-directory target-datetime]
   (let [files (->> (io/file snapshot-directory)
                    (.listFiles)
                    (map #(.getName %))
                    (filter #(str/starts-with? % "replik8s-snapshot-"))
                    (map #(hash-map :filename % :datetime (snapshot->datetime %)))
                    (filter #(-> % :datetime nil? not))
                    (vec))]
     (if (empty? files)
       nil
       (let [closest-file (reduce (fn [closest current]
                                    (if (nil? closest)
                                      current
                                      (let [closest-diff (java.time.Duration/between (:datetime closest) target-datetime)
                                            current-diff (java.time.Duration/between (:datetime current) target-datetime)]
                                        (if (< (Math/abs (.toMillis current-diff)) (Math/abs (.toMillis closest-diff)))
                                          current
                                          closest))))
                                  nil
                                  files)]
         (:filename closest-file))))))

(defn version-number? [x]
  (or (= "LATEST" x) (re-find #"(\d+\.?)+" x)))

(defn version-greater-or-equal?
  "Checks if version is greater than or equal to base version."
  [version-str base-version-str]
  (if (= version-str "LATEST")
    true
    (if (and (version-number? version-str) (version-number? base-version-str))
      (let [v-segs      (mapv parse-long (str/split version-str #"\."))
            base-segs   (mapv parse-long (str/split base-version-str #"\."))
            min-segs    (max (count v-segs) (count base-segs))
            v-padded    (into v-segs (repeat (- min-segs (count v-segs)) 0))
            base-padded (into base-segs (repeat (- min-segs (count base-segs)) 0))]
        (not (pos? (compare base-padded v-padded))))
      (throw (ex-info "Unable to compare version number formats" {:version version-str :base-version base-version-str})))))

(defn list-snapshots
  "List all snapshot files in the given directory."
  ([]
   (list-snapshots "snapshots"))
  ([directory]
   (->> (io/file directory)
        (.listFiles)
        (map #(.getName %))
        (filter #(clojure.string/starts-with? % "replik8s-snapshot-"))
        (map #(str directory "/" %)))))

(defn generate-kubeconfig-all-snapshots
  "Scans the snapshots directory and generates a kubeconfig JSON file with a cluster & context for each snapshot."
  ([]
   (generate-kubeconfig-all-snapshots "snapshots" "kubeconfig-all-snapshots.json"))
  ([snapshot-directory kubeconfig-path]
   (let [snapshot-times (map #(re-find #"\d{4}-\d{2}-\d{2}_\d{2}:\d{2}" %) (list-snapshots snapshot-directory))
         clusters   (map (fn [fname]
                           (let [name (str "snapshot-" fname)]
                             {:name    name
                              :cluster {:server                   (str "https://localhost:3443/" fname "/")
                                        :insecure-skip-tls-verify true}}))
                         snapshot-times)
         contexts   (map (fn [{:keys [name]}]
                           {:name    name
                            :context {:cluster name
                                      :user    "default"}})
                         clusters)
         kubeconfig {:apiVersion      "v1"
                     :kind            "Config"
                     :clusters        clusters
                     :contexts        contexts
                     :current-context (->> clusters (sort-by :name) last :name)
                     :users           [{:name "default" :user {:token "placeholder"}}]
                     :preferences {}}]
     (spit kubeconfig-path (json/write-str kubeconfig :escape-slash false)))))

(comment
  (datetime->date-str 1743693660000)

  (date-str->epoch "2025-05-03_10:11Z")

  (version-greater-or-equal? "1.0.1" "1.0.0"))
