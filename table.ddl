    CREATE TABLE `vuln_status` (
      `id` int unsigned not null auto_increment,
      `status` varchar(8),
      primary key (`id`)
    );
    INSERT INTO `vuln_status`
      (`status`)
    VALUES
      ('safe'),
      ('unsafe'),
      ('pending')
    ;
    CREATE TABLE `vuln_digest_status` (
      `id` int unsigned not null auto_increment,
      `digest` binary(16) not null,
      `status_id` int unsigned not null,
      primary key (`id`),
      index `vuln_digest_status_idx_status_id` (`status_id`),
      foreign key (`status_id`)
        references `vuln_status` (`id`)
        on delete restrict
        on update cascade
    );
    INSERT INTO `vuln_digest_status`
    (`digest`, `status_id`)
    VALUES
    (UNHEX('e3fc50a88d0a364313df4b21ef20c29e'), 1)
    ;
    CREATE TABLE `vuln_file_log` (
      `id` int unsigned not null auto_increment,
      `path` VARCHAR(4096) not null,
      `detected_on` TIMESTAMP not null,
      `digest_id` int unsigned not null,
      primary key (`id`),
      index `vuln_file_log_idx_digest_id` (`digest_id`),
      foreign key (`digest_id`)
        references `vuln_digest_status` (`id`)
        on delete restrict
        on update cascade
    );
INSERT INTO `vuln_file_log`
  (`path`, `detected_on`, `digest_id`)
VALUES
  ('/home', '2013-08-05 18:19:03', 1)
;

